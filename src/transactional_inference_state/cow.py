"""Structured paths and fine-grained copy-on-write private state."""
from __future__ import annotations

from copy import copy, deepcopy
from dataclasses import dataclass, field
import json
from typing import Any

from .runtime import InferenceState, SnapshotManager


@dataclass(frozen=True)
class DictKey:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("dictionary path keys must be non-empty strings")


@dataclass(frozen=True)
class ListIndex:
    value: int

    def __post_init__(self) -> None:
        if not isinstance(self.value, int) or self.value < 0:
            raise ValueError("list path indexes must be non-negative integers")


PathComponent = DictKey | ListIndex


@dataclass(frozen=True)
class FieldPath:
    field_name: str
    components: tuple[PathComponent, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.field_name, str) or not self.field_name:
            raise ValueError("field_name must be a non-empty string")
        if not self.components:
            raise ValueError("a field path requires at least one component")
        if not all(isinstance(item, (DictKey, ListIndex))
                   for item in self.components):
            raise TypeError("path components must be DictKey or ListIndex")

    @classmethod
    def keys(cls, field_name: str, *keys: str) -> "FieldPath":
        return cls(field_name, tuple(DictKey(key) for key in keys))

    def child(self, component: PathComponent) -> "FieldPath":
        return FieldPath(self.field_name, self.components + (component,))

    def canonical(self) -> str:
        parts = [self.field_name]
        for component in self.components:
            if isinstance(component, DictKey):
                encoded = component.value.replace("~", "~0").replace("/", "~1")
                parts.append(f"k:{encoded}")
            else:
                parts.append(f"i:{component.value}")
        return "/".join(parts)


_DELETED = object()


@dataclass
class COWContext:
    base: InferenceState
    roots: dict[tuple[str, PathComponent], Any] = field(default_factory=dict)
    modified_paths: dict[FieldPath, Any] = field(default_factory=dict)
    materialized: InferenceState | None = None
    copied_nodes: int = 0
    full_materialization_occurred: bool = False
    materialization_reason: str | None = None


@dataclass(frozen=True)
class COWAccounting:
    cow_paths_modified: int
    cow_nodes_copied: int
    cow_bytes_estimated: int
    logically_modified_nodes: int
    copy_amplification: float
    full_materialization_occurred: bool
    materialization_reason: str | None


class FineGrainedCOWStrategy:
    """Copies the mutable container chain for explicit nested-path mutations."""

    name = "fine_grained_cow"

    def begin(self, state: InferenceState) -> COWContext:
        return COWContext(base=state)

    def materialize(self, context: COWContext) -> InferenceState:
        if context.materialized is None:
            context.materialized = deepcopy(context.base)
            for (field_name, first), value in context.roots.items():
                container = getattr(context.materialized, field_name)
                if value is _DELETED:
                    _delete_component(container, first)
                else:
                    _set_component(container, first, deepcopy(value))
            context.full_materialization_occurred = True
            context.materialization_reason = "arbitrary_callback_mutation"
        return context.materialized

    def read(self, context: COWContext, field_name: str, key: Any) -> Any:
        component = _component_for_key(key)
        return self.read_path(context, FieldPath(field_name, (component,)))

    def write(self, context: COWContext, field_name: str,
              key: Any, value: Any) -> None:
        component = _component_for_key(key)
        self.write_path(context, FieldPath(field_name, (component,)), value)

    def delete(self, context: COWContext, field_name: str, key: Any) -> None:
        component = _component_for_key(key)
        self.delete_path(context, FieldPath(field_name, (component,)))

    def read_path(self, context: COWContext, path: FieldPath) -> Any:
        if context.materialized is not None:
            return deepcopy(_read_components(
                getattr(context.materialized, path.field_name), path.components
            ))
        first, remaining = path.components[0], path.components[1:]
        root_key = (path.field_name, first)
        if root_key in context.roots:
            value = context.roots[root_key]
            if value is _DELETED:
                raise KeyError(_raw(first))
            return deepcopy(_read_components(value, remaining))
        return deepcopy(_read_components(
            getattr(context.base, path.field_name), path.components
        ))

    def write_path(self, context: COWContext, path: FieldPath, value: Any) -> None:
        if context.materialized is not None:
            _write_components(
                getattr(context.materialized, path.field_name), path.components,
                deepcopy(value), delete=False,
            )
            context.modified_paths[path] = deepcopy(value)
            return
        self._modify_root(context, path, deepcopy(value), delete=False)

    def delete_path(self, context: COWContext, path: FieldPath) -> None:
        # Match normal deletion semantics by proving the path exists first.
        self.read_path(context, path)
        if context.materialized is not None:
            _write_components(
                getattr(context.materialized, path.field_name), path.components,
                None, delete=True,
            )
            context.modified_paths[path] = _DELETED
            return
        self._modify_root(context, path, None, delete=True)

    def commit(self, context: COWContext, state: InferenceState) -> None:
        if context.materialized is not None:
            SnapshotManager().restore(state, context.materialized)
            return
        for (field_name, first), value in context.roots.items():
            container = getattr(state, field_name)
            if value is _DELETED:
                _delete_component(container, first)
            else:
                _set_component(container, first, value)

    def accounting(self, context: COWContext) -> COWAccounting:
        encoded = json.dumps(
            {f"{field}:{_raw(component)}": value
             for (field, component), value in context.roots.items()
             if value is not _DELETED},
            default=repr, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        changed = sum(
            path.field_name != "provenance_metadata"
            for path in context.modified_paths
        )
        return COWAccounting(
            cow_paths_modified=changed,
            cow_nodes_copied=context.copied_nodes,
            cow_bytes_estimated=len(encoded),
            logically_modified_nodes=changed,
            copy_amplification=context.copied_nodes / max(1, changed),
            full_materialization_occurred=context.full_materialization_occurred,
            materialization_reason=context.materialization_reason,
        )

    def _modify_root(self, context: COWContext, path: FieldPath,
                     value: Any, *, delete: bool) -> None:
        first, remaining = path.components[0], path.components[1:]
        root_key = (path.field_name, first)
        if not remaining:
            context.roots[root_key] = _DELETED if delete else value
            context.modified_paths[path] = _DELETED if delete else deepcopy(value)
            return
        if root_key in context.roots:
            current = context.roots[root_key]
            if current is _DELETED:
                raise KeyError(_raw(first))
        else:
            current = _get_component(getattr(context.base, path.field_name), first)
        changed, copied = _copy_branch(current, remaining, value, delete=delete)
        context.roots[root_key] = changed
        context.copied_nodes += copied
        context.modified_paths[path] = _DELETED if delete else deepcopy(value)


def _component_for_key(key: Any) -> PathComponent:
    if isinstance(key, str):
        return DictKey(key)
    if isinstance(key, int):
        return ListIndex(key)
    raise TypeError("COW keys must be strings or non-negative integers")


def _raw(component: PathComponent) -> str | int:
    return component.value


def _get_component(container: Any, component: PathComponent) -> Any:
    if isinstance(component, DictKey):
        if not isinstance(container, dict):
            raise TypeError("DictKey requires a dictionary container")
        return container[component.value]
    if not isinstance(container, list):
        raise TypeError("ListIndex requires a list container")
    return container[component.value]


def _set_component(container: Any, component: PathComponent, value: Any) -> None:
    if isinstance(component, DictKey):
        if not isinstance(container, dict):
            raise TypeError("DictKey requires a dictionary container")
        container[component.value] = value
    else:
        if not isinstance(container, list):
            raise TypeError("ListIndex requires a list container")
        container[component.value] = value


def _delete_component(container: Any, component: PathComponent) -> None:
    if isinstance(component, DictKey):
        if not isinstance(container, dict):
            raise TypeError("DictKey requires a dictionary container")
        del container[component.value]
    else:
        if not isinstance(container, list):
            raise TypeError("ListIndex requires a list container")
        del container[component.value]


def _read_components(container: Any,
                     components: tuple[PathComponent, ...]) -> Any:
    value = container
    for component in components:
        value = _get_component(value, component)
    return value


def _write_components(container: Any, components: tuple[PathComponent, ...],
                      value: Any, *, delete: bool) -> None:
    parent = _read_components(container, components[:-1])
    if delete:
        _delete_component(parent, components[-1])
    else:
        _set_component(parent, components[-1], value)


def _copy_branch(container: Any, components: tuple[PathComponent, ...],
                 value: Any, *, delete: bool) -> tuple[Any, int]:
    local = copy(container)
    component = components[0]
    if len(components) == 1:
        if delete:
            _delete_component(local, component)
        else:
            _set_component(local, component, value)
        return local, 1
    child = _get_component(container, component)
    changed, copied = _copy_branch(
        child, components[1:], value, delete=delete
    )
    _set_component(local, component, changed)
    return local, copied + 1
