"""Opt-in integration test for a disposable localhost Redis instance."""
import os
import pytest
import transactional_inference_state as tis

pytestmark = pytest.mark.skipif(
    not os.environ.get("TIS_REDIS_PORT"),
    reason="set TIS_REDIS_PORT for an explicitly managed localhost Redis",
)

def test_real_redis_commit_isolation_and_rollback():
    transport = tis.SocketRedisTransport(port=int(os.environ["TIS_REDIS_PORT"]), database=15)
    sessions = tis.SessionManager(); sessions.create_session("S"); sessions.create_session("T")
    manager = tis.TransactionManager(sessions)
    participant = tis.RedisTransactionalParticipant(
        manager, transport, key_prefix="tis-integration-test:")
    coordinator = tis.RedisTransactionCoordinator(manager)
    seed = coordinator.begin("S", participant); participant.set(seed, "S", "value", b"committed")
    manager.validate(seed); coordinator.commit(seed)
    rejected = coordinator.begin("S", participant); participant.set(rejected, "S", "value", b"tentative")
    assert participant.get(rejected, "S", "value").value == b"tentative"
    observer = coordinator.begin("T", participant)
    assert participant.get(observer, "T", "value").value == b"committed"
    manager.validate(observer); coordinator.commit(observer)
    manager.validator = tis.PolicyValidator(False); manager.validate(rejected); coordinator.rollback(rejected)
    verify = coordinator.begin("S", participant)
    assert participant.get(verify, "S", "value").value == b"committed"
    participant.set(verify, "S", "value", b"stale-write")
    concurrent = coordinator.begin("T", participant); participant.set(concurrent, "T", "value", b"concurrent")
    manager.validator = tis.PolicyValidator(True); manager.validate(concurrent); coordinator.commit(concurrent)
    manager.validate(verify)
    with pytest.raises(tis.RedisConflictError): coordinator.commit(verify)
    assert manager.status(verify) is tis.TransactionStatus.ROLLED_BACK
    cleanup = coordinator.begin("S", participant); participant.delete(cleanup, "S", "value")
    manager.validate(cleanup); coordinator.commit(cleanup)
