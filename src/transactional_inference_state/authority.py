"""Runtime-issued action authority, deliberately separate from provenance and flow."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .provenance import ProvenanceRegistry,RuntimeSourceType,TrustLabel

@dataclass(frozen=True)
class AuthorityGrant:
    grant_id:str
    principal_user:str
    principal_session:str
    permissions:frozenset[str]
    scope:str
    issuer:str
    reason:str
    source_provenance_ids:tuple[str,...]
    transaction_id:str
    created_by_runtime:bool=True

@dataclass(frozen=True)
class AuthorityContext:
    principal_user:str
    principal_session:str
    permissions:frozenset[str]
    scope:str
    authority_source_ids:tuple[str,...]
    issued_by:tuple[str,...]
    transaction_ids:tuple[str,...]

@dataclass(frozen=True)
class AuthorityDecision:
    allowed:bool
    permission:str
    scope:str
    reasons:tuple[str,...]
    grant_ids:tuple[str,...]=()

class AuthorityRegistry:
    """Issues grants only from committed, trusted authoritative provenance.

    Ordinary derivation never creates permissions.  A derived context is merely
    the intersection of valid input grants still bound to the same principal and
    requested scope.
    """
    def __init__(self,provenance:ProvenanceRegistry,event_log:Any|None=None,*,trusted_issuers:frozenset[str]=frozenset({"runtime","security-reviewer","system"})):
        self.provenance=provenance;self.event_log=event_log;self.trusted_issuers=trusted_issuers;self._grants={};self._next=1

    def issue(self,*,principal_user:str,principal_session:str,permissions:frozenset[str],scope:str,issuer:str,reason:str,source_provenance_ids:tuple[str,...],transaction_id:str)->AuthorityGrant:
        if not all((principal_user,principal_session,permissions,scope,issuer,reason,source_provenance_ids,transaction_id)):raise ValueError("authority grant fields must be non-empty")
        if issuer not in self.trusted_issuers:raise PermissionError("issuer is not trusted to grant authority")
        records=tuple(self.provenance.get(x) for x in source_provenance_ids)
        if any(not x.created_by_runtime or not x.committed or x.trust_label is not TrustLabel.TRUSTED or x.source_type not in {RuntimeSourceType.SYSTEM_CONTEXT,RuntimeSourceType.USER_INPUT,RuntimeSourceType.USER_PROMPT} for x in records):raise PermissionError("authority requires committed trusted authoritative provenance")
        grant=AuthorityGrant(f"authority-{self._next:06d}",principal_user,principal_session,frozenset(permissions),scope,issuer,reason,tuple(source_provenance_ids),transaction_id,True);self._next+=1;self._grants[grant.grant_id]=grant
        if self.event_log is not None:self.event_log.record("AUTHORITY_GRANTED",transaction_id,session_id=principal_session,grant_id=grant.grant_id,permissions=tuple(sorted(permissions)),scope=scope,issuer=issuer,source_provenance_ids=source_provenance_ids)
        return grant

    def context(self,*,principal_user:str,principal_session:str,scope:str,grant_ids:tuple[str,...]=())->AuthorityContext:
        grants=[]
        for grant_id in grant_ids:
            grant=self._grants.get(grant_id)
            if grant is not None and grant.created_by_runtime and grant.principal_user==principal_user and grant.principal_session==principal_session and grant.scope==scope:grants.append(grant)
        permissions=frozenset().union(*(x.permissions for x in grants)) if grants else frozenset()
        return AuthorityContext(principal_user,principal_session,permissions,scope,tuple(x for grant in grants for x in grant.source_provenance_ids),tuple(x.issuer for x in grants),tuple(x.transaction_id for x in grants))

    def derive(self,contexts:tuple[AuthorityContext,...],*,principal_user:str,principal_session:str,scope:str)->AuthorityContext:
        valid=[x for x in contexts if x.principal_user==principal_user and x.principal_session==principal_session and x.scope==scope]
        if not valid:return self.context(principal_user=principal_user,principal_session=principal_session,scope=scope)
        permissions=frozenset.intersection(*(x.permissions for x in valid)) if len(valid)>1 else valid[0].permissions
        return AuthorityContext(principal_user,principal_session,permissions,scope,tuple(dict.fromkeys(x for item in valid for x in item.authority_source_ids)),tuple(dict.fromkeys(x for item in valid for x in item.issued_by)),tuple(dict.fromkeys(x for item in valid for x in item.transaction_ids)))

    def authorize(self,context:AuthorityContext,*,permission:str,scope:str,principal_user:str,principal_session:str)->AuthorityDecision:
        identity=context.principal_user==principal_user and context.principal_session==principal_session;scoped=context.scope==scope;allowed=identity and scoped and permission in context.permissions
        reasons=[]
        if not identity:reasons.append("PRINCIPAL_SCOPE_MISMATCH")
        if not scoped:reasons.append("RESOURCE_SCOPE_MISMATCH")
        if permission not in context.permissions:reasons.append("MISSING_AUTHORITY_GRANT")
        grant_ids=tuple(x.grant_id for x in self._grants.values() if x.principal_user==principal_user and x.principal_session==principal_session and x.scope==scope and permission in x.permissions)
        return AuthorityDecision(allowed,permission,scope,tuple(reasons) if reasons else ("VALID_RUNTIME_AUTHORITY_GRANT",),grant_ids if allowed else ())

    def get(self,grant_id:str)->AuthorityGrant:return self._grants[grant_id]
    @property
    def grants(self)->tuple[AuthorityGrant,...]:return tuple(self._grants.values())
