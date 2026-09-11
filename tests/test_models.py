from sentinel.models import CollectionError, CollectionResult


def test_collection_result_is_ok_without_errors() -> None:
    result = CollectionResult(data=["telemetry"])

    assert result.ok is True
    assert result.errors == ()
    assert result.collected_at.tzinfo is not None


def test_collection_result_exposes_non_fatal_errors() -> None:
    error = CollectionError.from_exception("process.42", PermissionError("denied"))
    result = CollectionResult(data=[], errors=(error,))

    assert result.ok is False
    assert error.scope == "process.42"
    assert error.error_type == "PermissionError"
