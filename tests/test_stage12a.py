from dataclasses import FrozenInstanceError

import pytest

import transactional_inference_state as tis


def runtime(*, effects=False):
    sessions = tis.SessionManager()
    sessions.create_session("A", user_id="alice")
    sessions.create_session("B", user_id="bob")
    effect_manager = None
    if effects:
        effect_manager = tis.EffectManager(tis.FakeEmailService())
    manager = tis.TransactionManager(
        sessions, shared_state=tis.SharedState(), effect_manager=effect_manager
    )
    return sessions, manager, effect_manager


def issue(manager, transaction, source=tis.RuntimeSourceType.USER_PROMPT,
          trust=tis.TrustLabel.TRUSTED, parents=()):
    return manager.issue_provenance(
        transaction, source, trust_label=trust,
        parent_source_ids=tuple(item.source_id for item in parents),
    )


def test_runtime_issues_immutable_authoritative_label():
    _, manager, _ = runtime()
    transaction = manager.begin("A")
    record = issue(manager, transaction)
    label = manager.provenance_registry.labels((record.source_id,))[0]
    assert label == tis.ProvenanceLabel(
        "alice", "A", transaction, record.source_id,
        tis.RuntimeSourceType.USER_PROMPT, tis.TrustLabel.TRUSTED,
    )
    with pytest.raises(FrozenInstanceError):
        label.user_id = "mallory"
    manager.rollback(transaction)


@pytest.mark.parametrize("strategy", [tis.FullCopyStrategy(), tis.DeltaStrategy()])
def test_rollback_removes_tentative_value_and_lineage(strategy):
    sessions, manager, _ = runtime()
    manager.snapshot_strategy = strategy
    transaction = manager.begin("A")
    record = issue(manager, transaction)
    manager.write_private(
        transaction, "A", "session_memory", "draft", "tentative",
        provenance_ids=(record.source_id,),
    )
    assert manager.read_private_provenanced(
        transaction, "A", "session_memory", "draft"
    ).provenance[0].source_id == record.source_id
    manager.rollback(transaction)
    assert "draft" not in sessions.get_session("A").session_memory
    assert sessions.get_session("A").provenance_metadata == {}
    assert not manager.provenance_registry.contains(record.source_id)


def test_commit_persists_value_and_provenance_together():
    sessions, manager, _ = runtime()
    transaction = manager.begin("A")
    record = issue(manager, transaction)
    manager.write_private(
        transaction, "A", "application_cache", "answer", 42,
        provenance_ids=(record.source_id,),
    )
    manager.validate(transaction)
    manager.commit(transaction)
    assert sessions.get_session("A").application_cache["answer"] == 42
    committed = manager.provenance_for_private(
        "A", "application_cache", "answer"
    )
    assert committed[0].source_id == record.source_id
    assert committed[0].committed is True


def test_derived_value_records_multiple_parent_sources():
    _, manager, _ = runtime()
    transaction = manager.begin("A")
    user = issue(manager, transaction)
    retrieval = issue(
        manager, transaction, tis.RuntimeSourceType.RETRIEVED_CONTENT,
        tis.TrustLabel.UNTRUSTED,
    )
    summary = issue(
        manager, transaction, tis.RuntimeSourceType.DERIVED_VALUE,
        tis.TrustLabel.MIXED, (user, retrieval),
    )
    lineage = manager.provenance_registry.lineage((summary.source_id,))
    assert {item.source_id for item in lineage} == {
        user.source_id, retrieval.source_id, summary.source_id
    }
    assert summary.parent_source_ids == (user.source_id, retrieval.source_id)
    manager.rollback(transaction)


def test_shared_state_preserves_session_a_origin_when_session_b_reads():
    _, manager, _ = runtime()
    transaction_a = manager.begin("A")
    source = issue(manager, transaction_a)
    manager.write_shared(
        transaction_a, "shared-summary", "A-derived",
        provenance_ids=(source.source_id,),
    )
    manager.validate(transaction_a)
    manager.commit(transaction_a)
    transaction_b = manager.begin("B")
    observed = manager.read_shared_provenanced(transaction_b, "shared-summary")
    assert observed.value == "A-derived"
    assert observed.provenance[0].session_id == "A"
    assert observed.provenance[0].user_id == "alice"
    manager.rollback(transaction_b)


def test_model_claim_cannot_replace_runtime_provenance():
    _, manager, _ = runtime()
    transaction = manager.begin("A")
    runtime_source = issue(
        manager, transaction, tis.RuntimeSourceType.RETRIEVED_CONTENT,
        tis.TrustLabel.UNTRUSTED,
    )
    plan = tis.parse_model_plan(
        '{"operations":[{"operation_id":"write","operation_type":'
        '"MEMORY_WRITE","arguments":{"key":"claim","value":"x"},'
        '"source":"user_prompt"}],"final_response":"done"}'
    )
    tis.OperationExecutor(manager).execute(
        plan, transaction, "A",
        runtime_provenance={"write": (runtime_source.source_id,)},
    )
    manager.validate(transaction)
    manager.commit(transaction)
    committed = manager.provenance_for_private(
        "A", "session_memory", "claim"
    )[0]
    assert plan.operations[0].source is tis.Provenance.USER_PROMPT
    assert committed.source_type is tis.RuntimeSourceType.RETRIEVED_CONTENT
    assert committed.trust_label is tis.TrustLabel.UNTRUSTED


def test_unregistered_provenance_id_is_rejected():
    _, manager, _ = runtime()
    transaction = manager.begin("A")
    with pytest.raises(tis.TransactionError, match="not issued"):
        manager.write_private(
            transaction, "A", "session_memory", "forged", True,
            provenance_ids=("model-invented-source",),
        )
    manager.rollback(transaction)


def test_pending_effect_carries_provenance_and_rollback_discards_reference():
    _, manager, effects = runtime(effects=True)
    transaction = manager.begin("A")
    source = issue(manager, transaction)
    pending = tis.TransactionalTools(effects, transaction, "A").send_email(
        to="a@example.test", subject="x", body="y",
        provenance_ids=(source.source_id,),
    )
    assert pending.provenance_ids == (source.source_id,)
    manager.rollback(transaction)
    discarded = effects.list_effects(transaction, "A")[0]
    assert discarded.status is tis.EffectStatus.DISCARDED
    assert discarded.provenance_ids == ()
    assert not manager.provenance_registry.contains(source.source_id)


def test_committed_effect_retains_committed_provenance():
    _, manager, effects = runtime(effects=True)
    transaction = manager.begin("A")
    source = issue(manager, transaction)
    tis.TransactionalTools(effects, transaction, "A").send_email(
        to="a@example.test", subject="x", body="y",
        provenance_ids=(source.source_id,),
    )
    manager.validate(transaction)
    manager.commit(transaction)
    effect = effects.list_effects(transaction, "A")[0]
    assert effect.provenance_ids == (source.source_id,)
    assert manager.provenance_registry.get(source.source_id).committed


def test_provenance_policy_hook_receives_runtime_records():
    class RejectUntrusted:
        def evaluate_provenance(self, context):
            untrusted = any(
                source.trust_label is tis.TrustLabel.UNTRUSTED
                for source in context.sources
            )
            return tis.ProvenancePolicyDecision(
                not untrusted, ("UNTRUSTED_FLOW",) if untrusted else ()
            )

    _, manager, _ = runtime()
    transaction = manager.begin("A")
    source = issue(
        manager, transaction, tis.RuntimeSourceType.RETRIEVED_CONTENT,
        tis.TrustLabel.UNTRUSTED,
    )
    decision = manager.evaluate_provenance(
        transaction, RejectUntrusted(), destination="shared",
        source_ids=(source.source_id,),
    )
    assert not decision.allowed
    assert decision.reasons == ("UNTRUSTED_FLOW",)
    manager.rollback(transaction)


def test_provenance_audit_events_cover_full_lifecycle():
    _, manager, _ = runtime()
    transaction = manager.begin("A")
    parent = issue(manager, transaction)
    child = issue(
        manager, transaction, tis.RuntimeSourceType.DERIVED_VALUE,
        parents=(parent,),
    )
    manager.write_private(
        transaction, "A", "session_memory", "derived", "value",
        provenance_ids=(child.source_id,),
    )
    manager.read_private_provenanced(
        transaction, "A", "session_memory", "derived"
    )
    manager.validate(transaction)
    manager.commit(transaction)
    types = [event.event_type for event in manager.event_log.events]
    assert "PROVENANCE_CREATED" in types
    assert "PROVENANCE_DERIVED" in types
    assert "PROVENANCE_READ" in types
    assert types.count("PROVENANCE_COMMITTED") == 2


def test_stage12a_experiment_answers_all_four_research_questions():
    result = tis.run_provenance_experiments()
    assert result.committed_origin_identified
    assert result.commit_preserved_provenance
    assert result.rollback_removed_value
    assert result.rollback_removed_lineage
    assert result.cross_session_origin_preserved
    assert result.claimed_provenance_overrode_runtime is False
    assert result.effect_provenance_attached
