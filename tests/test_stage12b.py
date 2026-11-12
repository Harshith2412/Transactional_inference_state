from dataclasses import FrozenInstanceError

import pytest

import transactional_inference_state as tis


def cow_runtime(memory=None):
    sessions = tis.SessionManager()
    state = sessions.create_session("S", user_id="U")
    state.session_memory = memory or {}
    manager = tis.TransactionManager(
        sessions, snapshot_strategy=tis.FineGrainedCOWStrategy()
    )
    return state, manager


def test_structured_field_path_is_typed_immutable_and_canonical():
    path = tis.FieldPath(
        "tool_results",
        (tis.ListIndex(3), tis.DictKey("email/address")),
    )
    assert path.canonical() == "tool_results/i:3/k:email~1address"
    with pytest.raises(FrozenInstanceError):
        path.field_name = "scratchpad"
    with pytest.raises(ValueError):
        tis.FieldPath("session_memory", ())
    with pytest.raises(ValueError):
        tis.ListIndex(-1)


def test_nested_read_returns_safe_copy_without_creating_cow_nodes():
    state, manager = cow_runtime({"profile": {"permissions": ["read"]}})
    transaction = manager.begin("S")
    path = tis.FieldPath.keys("session_memory", "profile", "permissions")
    observed = manager.read_path(transaction, "S", path)
    observed.append("admin")
    assert state.session_memory["profile"]["permissions"] == ["read"]
    assert manager.read_path(transaction, "S", path) == ["read"]
    assert manager.cow_accounting(transaction).cow_nodes_copied == 0
    manager.rollback(transaction)


def test_nested_dictionary_write_is_tentative_and_rolls_back_exactly():
    state, manager = cow_runtime({"profile": {"auth": {"share": False}}})
    before = tis.state_digest(state)
    transaction = manager.begin("S")
    path = tis.FieldPath.keys("session_memory", "profile", "auth", "share")
    manager.write_path(transaction, "S", path, True)
    assert manager.read_path(transaction, "S", path) is True
    assert state.session_memory["profile"]["auth"]["share"] is False
    manager.rollback(transaction)
    assert tis.state_digest(state) == before


def test_nested_dictionary_write_commits_only_changed_branch():
    preferences = {"editor": "VS Code"}
    state, manager = cow_runtime({
        "profile": {"name": "Alice", "preferences": preferences,
                    "auth": {"share": False}}
    })
    transaction = manager.begin("S")
    path = tis.FieldPath.keys("session_memory", "profile", "auth", "share")
    manager.write_path(transaction, "S", path, True)
    manager.validate(transaction)
    manager.commit(transaction)
    assert state.session_memory["profile"]["auth"]["share"] is True
    assert state.session_memory["profile"]["preferences"] is preferences


@pytest.mark.parametrize("outcome", ["rollback", "commit"])
def test_nested_delete_preserves_or_removes_value_and_provenance(outcome):
    state, manager = cow_runtime({"profile": {"keep": 1, "temporary": 2}})
    path = tis.FieldPath.keys("session_memory", "profile", "temporary")
    transaction = manager.begin("S")
    source = manager.issue_provenance(
        transaction, tis.RuntimeSourceType.USER_INPUT,
        trust_label=tis.TrustLabel.TRUSTED,
    )
    manager.write_path(
        transaction, "S", path, 2, provenance_ids=(source.source_id,)
    )
    manager.validate(transaction)
    manager.commit(transaction)
    original_ids = tuple(x.source_id for x in manager.provenance_for_path("S", path))
    transaction = manager.begin("S")
    manager.delete_path(transaction, "S", path)
    with pytest.raises(KeyError):
        manager.read_path(transaction, "S", path)
    assert state.session_memory["profile"]["temporary"] == 2
    if outcome == "commit":
        manager.validate(transaction)
        manager.commit(transaction)
        assert "temporary" not in state.session_memory["profile"]
        assert manager.provenance_for_path("S", path) == ()
    else:
        manager.rollback(transaction)
        assert state.session_memory["profile"]["temporary"] == 2
        assert tuple(x.source_id for x in manager.provenance_for_path("S", path)) == original_ids
    assert state.session_memory["profile"]["keep"] == 1


def test_nested_list_field_has_independent_provenance():
    state, manager = cow_runtime({"result": {"rows": [
        {"name": "Alice", "email": "alice@example.test"},
        {"name": "Bob", "email": "bob@example.test"},
    ]}})
    transaction = manager.begin("S")
    source = manager.issue_provenance(
        transaction, tis.RuntimeSourceType.RETRIEVED_CONTENT,
        trust_label=tis.TrustLabel.UNTRUSTED,
    )
    email = tis.FieldPath("session_memory", (
        tis.DictKey("result"), tis.DictKey("rows"), tis.ListIndex(1),
        tis.DictKey("email"),
    ))
    manager.write_path(
        transaction, "S", email, "changed@example.test",
        provenance_ids=(source.source_id,),
    )
    manager.validate(transaction)
    manager.commit(transaction)
    assert manager.provenance_for_path("S", email)[0].trust_label is tis.TrustLabel.UNTRUSTED
    assert state.session_memory["result"]["rows"][0]["email"] == "alice@example.test"
    assert state.session_memory["result"]["rows"][1]["name"] == "Bob"


def test_independent_sibling_provenance_survives_field_replacement():
    state, manager = cow_runtime({"profile": {"name": "Alice", "role": "user"}})
    name = tis.FieldPath.keys("session_memory", "profile", "name")
    role = tis.FieldPath.keys("session_memory", "profile", "role")
    transaction = manager.begin("S")
    trusted = manager.issue_provenance(
        transaction, tis.RuntimeSourceType.USER_INPUT,
        trust_label=tis.TrustLabel.TRUSTED,
    )
    manager.write_path(transaction, "S", name, "Alice",
                       provenance_ids=(trusted.source_id,))
    manager.validate(transaction); manager.commit(transaction)
    transaction = manager.begin("S")
    untrusted = manager.issue_provenance(
        transaction, tis.RuntimeSourceType.RETRIEVED_CONTENT,
        trust_label=tis.TrustLabel.UNTRUSTED,
    )
    manager.write_path(transaction, "S", role, "admin",
                       provenance_ids=(untrusted.source_id,))
    manager.validate(transaction); manager.commit(transaction)
    assert manager.provenance_for_path("S", name)[0].source_id == trusted.source_id
    assert manager.provenance_for_path("S", role)[0].source_id == untrusted.source_id


def test_field_level_multi_parent_provenance_does_not_taint_sibling():
    _, manager = cow_runtime({"profile": {"summary": "old", "name": "Alice"}})
    summary = tis.FieldPath.keys("session_memory", "profile", "summary")
    name = tis.FieldPath.keys("session_memory", "profile", "name")
    transaction = manager.begin("S")
    one = manager.issue_provenance(transaction, tis.RuntimeSourceType.USER_INPUT,
                                   trust_label=tis.TrustLabel.TRUSTED)
    two = manager.issue_provenance(transaction, tis.RuntimeSourceType.RETRIEVED_CONTENT,
                                   trust_label=tis.TrustLabel.UNTRUSTED)
    derived = manager.issue_provenance(
        transaction, tis.RuntimeSourceType.DERIVED_VALUE,
        trust_label=tis.TrustLabel.MIXED,
        parent_source_ids=(one.source_id, two.source_id),
    )
    manager.write_path(transaction, "S", summary, "combined",
                       provenance_ids=(derived.source_id,))
    manager.validate(transaction); manager.commit(transaction)
    lineage = manager.provenance_registry.lineage((derived.source_id,))
    assert {x.source_id for x in lineage} == {
        one.source_id, two.source_id, derived.source_id
    }
    assert manager.provenance_for_path("S", name) == ()


def test_alias_safety_breaks_only_modified_branch_alias():
    permissions = ["read"]
    state, manager = cow_runtime({
        "profile_A": {"permissions": permissions},
        "profile_B": {"permissions": permissions},
    })
    path = tis.FieldPath(
        "session_memory",
        (tis.DictKey("profile_A"), tis.DictKey("permissions"), tis.ListIndex(0)),
    )
    transaction = manager.begin("S")
    manager.write_path(transaction, "S", path, "admin")
    assert manager.read_path(transaction, "S", path) == "admin"
    assert state.session_memory["profile_A"]["permissions"] == ["read"]
    assert state.session_memory["profile_B"]["permissions"] == ["read"]
    manager.validate(transaction); manager.commit(transaction)
    assert state.session_memory["profile_A"]["permissions"] == ["admin"]
    assert state.session_memory["profile_B"]["permissions"] == ["read"]
    assert state.session_memory["profile_A"]["permissions"] is not permissions
    assert state.session_memory["profile_B"]["permissions"] is permissions


def test_no_transaction_local_copy_exists_until_explicit_mutation():
    state, manager = cow_runtime({"profile": {"nested": {"value": 1}}})
    profile_identity = id(state.session_memory["profile"])
    transaction = manager.begin("S")
    assert manager.cow_accounting(transaction).cow_nodes_copied == 0
    manager.read_path(
        transaction, "S", tis.FieldPath.keys(
            "session_memory", "profile", "nested", "value"
        )
    )
    assert manager.cow_accounting(transaction).cow_nodes_copied == 0
    manager.write_path(
        transaction, "S", tis.FieldPath.keys(
            "session_memory", "profile", "nested", "value"
        ), 2,
    )
    assert manager.cow_accounting(transaction).cow_nodes_copied == 2
    assert id(state.session_memory["profile"]) == profile_identity
    manager.rollback(transaction)


def test_callback_mutation_falls_back_to_full_materialization_and_is_safe():
    state, manager = cow_runtime({"profile": {"permissions": ["read"]}})
    before = tis.state_digest(state)
    transaction = manager.begin("S")
    manager.mutate(
        transaction, "S",
        lambda local: local.session_memory["profile"]["permissions"].append("admin"),
    )
    accounting = manager.cow_accounting(transaction)
    assert accounting.full_materialization_occurred
    assert accounting.materialization_reason == "arbitrary_callback_mutation"
    assert state.session_memory["profile"]["permissions"] == ["read"]
    manager.rollback(transaction)
    assert tis.state_digest(state) == before


def test_copy_amplification_is_node_based_and_explicit():
    _, manager = cow_runtime({"profile": {"a": {"b": {"value": 1}}}})
    transaction = manager.begin("S")
    manager.write_path(
        transaction, "S",
        tis.FieldPath.keys("session_memory", "profile", "a", "b", "value"), 2,
    )
    accounting = manager.cow_accounting(transaction)
    assert accounting.cow_paths_modified == 1
    assert accounting.cow_nodes_copied == 3
    assert accounting.copy_amplification == 3.0
    manager.rollback(transaction)


def test_shared_state_conflicts_remain_key_granularity_with_cow_private_state():
    sessions = tis.SessionManager(); sessions.create_session("A"); sessions.create_session("B")
    manager = tis.TransactionManager(
        sessions, shared_state=tis.SharedState({"cache": {"role": "user"}}),
        snapshot_strategy=tis.FineGrainedCOWStrategy(),
    )
    a, b = manager.begin("A"), manager.begin("B")
    manager.read_shared(a, "cache"); manager.read_shared(b, "cache")
    manager.write_shared(a, "cache", {"role": "admin"})
    manager.write_shared(b, "cache", {"role": "auditor"})
    manager.validate(a); manager.validate(b); manager.commit(a)
    with pytest.raises(tis.WriteConflictError): manager.commit(b)


def test_benchmark_schema_contains_all_strategies_and_integrity_fields():
    records = tis.run_cow_benchmark(
        sizes=("10KB",), mutation_ratios=(0.01,), depths=(3,), iterations=1
    )
    assert len(records) == 6
    assert {row.strategy for row in records} == {
        "full_copy", "delta", "fine_grained_cow"
    }
    assert all(row.rollback_integrity and row.provenance_integrity for row in records)
    assert all(row.copy_amplification >= 0 for row in records)


@pytest.mark.parametrize("outcome", ["rollback", "commit"])
def test_flagship_nested_field_experiment(outcome):
    result = tis.run_flagship_cow_experiment(outcome)
    assert result.committed_before is False
    assert result.tentative_value is True
    assert result.committed_after is (outcome == "commit")
    assert result.structural_integrity
    assert result.modified_field_new_provenance
    assert result.name_provenance_unchanged
    assert result.editor_provenance_unchanged
    assert result.copied_nodes == 2
    assert result.modified_paths == 1
    assert not result.full_materialization_occurred
    if outcome == "rollback":
        assert result.tentative_provenance_disappeared


def test_cow_provenance_microbenchmark_schema():
    result = tis.benchmark_cow_provenance_overhead(10)
    assert result.iterations == 10
    assert result.mutation_without_provenance_median_ns > 0
    assert result.mutation_with_provenance_median_ns > 0
