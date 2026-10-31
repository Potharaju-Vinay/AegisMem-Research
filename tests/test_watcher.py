from unittest.mock import patch

from core.security.watcher import AegisMemWatcher


def test_watcher_detects_same_version_content_change():
    watcher = AegisMemWatcher()

    original = {
        "version": 1,
        "revision_id": "revision-1",
        "content_hash": "original-hash",
        "status": "ACTIVE",
        "content": "Refunds allowed within 30 days.",
    }

    tampered = {
        **original,
        "content": "Refunds allowed within 365 days.",
    }

    states = [original, tampered, tampered]

    with patch.object(
        watcher, "get_memory_ids", return_value=["TEST-POLICY"]
    ), patch.object(
        watcher, "get_latest_record_state", side_effect=states
    ), patch.object(
        watcher,
        "process_memory",
        return_value={"detected": True, "recovered": False},
    ) as process:

        first_scan = watcher.scan_once()
        second_scan = watcher.scan_once()

    assert first_scan == []
    assert len(second_scan) == 1
    assert second_scan[0]["memory_id"] == "TEST-POLICY"
    assert second_scan[0]["observed_version"] == 1
    assert second_scan[0]["change_detected"] is True
    assert second_scan[0]["result"]["detected"] is True
    process.assert_called_once_with("TEST-POLICY")
