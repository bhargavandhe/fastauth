from __future__ import annotations

from authkit.domain import enums


def test_provider_id_values() -> None:
    assert enums.ProviderId.CREDENTIAL.value == "credential"
    assert enums.ProviderId.EMAIL_OTP.value == "email-otp"


def test_verification_purpose_values() -> None:
    assert enums.VerificationPurpose.EMAIL_VERIFICATION.value == "email-verification"
    assert enums.VerificationPurpose.PASSWORD_RESET.value == "password-reset"
    assert enums.VerificationPurpose.ACCOUNT_DELETION.value == "account-deletion"


def test_audit_event_type_covers_v1_events() -> None:
    required = {
        "user_signed_up",
        "user_signed_in",
        "user_signed_out",
        "user_email_verified",
        "user_updated",
        "user_email_change_requested",
        "user_email_changed",
        "user_delete_requested",
        "user_deleted",
        "session_created",
        "session_revoked",
        "sessions_revoked_all",
        "account_linked",
        "account_unlinked",
        "password_changed",
        "password_reset_requested",
        "password_reset_completed",
        "email_verification_sent",
        "api_key_created",
        "api_key_revoked",
        "api_key_verified_failed",
        "security_velocity_exceeded",
    }
    actual = {event.value for event in enums.AuditEventType}
    missing = required - actual
    assert not missing, f"missing audit events: {missing}"


def test_session_strategy_kind() -> None:
    assert {kind.value for kind in enums.SessionStrategyKind} == {"database", "jwt"}


def test_token_type() -> None:
    assert {kind.value for kind in enums.TokenType} == {"session", "verification", "api-key"}
