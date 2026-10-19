from datetime import UTC, datetime, timedelta

from bson import ObjectId

from fastauth.domain.models import RefreshToken
from fastauth.storage.beanie.documents import from_refresh_token, to_refresh_token


def test_mongo_refresh_jwt_sid_is_a_protocol_string() -> None:
    token = RefreshToken(
        id=str(ObjectId()),
        user_id=str(ObjectId()),
        session_id="jwt:" + "a" * 32,
        token_hash="hash",
        family_id=str(ObjectId()),
        family_created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    document = from_refresh_token(token)
    assert document.session_id == token.session_id
    assert isinstance(document.user_id, ObjectId)
    assert isinstance(document.family_id, ObjectId)
    assert to_refresh_token(document).session_id == token.session_id
