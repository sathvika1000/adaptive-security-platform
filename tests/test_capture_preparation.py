import json
from hashlib import sha256

import pytest

from adaptive_security.capture_preparation import prepare
from adaptive_security.capture_validation import freeze

RAW = b"ElfFile\0controlled header-only preparation fixture"
RULE = "auth.kerberos_password_spray"
START = "2020-01-01T00:00:00Z"
END = "2020-01-01T00:05:00Z"


def source(tmp_path, raw=RAW):
    path = tmp_path / "original.evtx"
    path.write_bytes(raw)
    return path


def metadata(tmp_path, **updates):
    data = {
        "version": 1,
        "exporter": "asp.security_export.v1",
        "capture_id": "auth-window",
        "capture_file": "Security.evtx",
        "channel": "Security",
        "capture_sha256": sha256(RAW).hexdigest(),
        "bytes": len(RAW),
        "record_count": 7,
        "collection_start": START,
        "collection_end": END,
        "exported_at": "2020-01-01T00:06:00Z",
        "environment": "private lab",
        "machine": "private-host",
        "query": "complete Security interval",
        **updates,
    }
    path = tmp_path / "collection.json"
    path.write_text(json.dumps(data))
    return path


def test_prepare_copies_evidence_creates_unlabeled_plan_and_freezes_without_parsing(
    tmp_path, monkeypatch
):
    import adaptive_security.capture_validation as module

    original = source(tmp_path)
    output = tmp_path / "prepared"
    plan = prepare(original, output, RULE, start=START, end=END, environment="private lab")
    (entry,) = plan.captures
    assert entry.label == "unlabeled" and entry.partition == "development"
    assert (output / "Security.evtx").read_bytes() == original.read_bytes()
    assert (output / "review-notes.md").exists()
    monkeypatch.setattr(
        module, "load_capture", lambda *args: pytest.fail("preparation parsed records")
    )
    frozen = freeze(output / "plan.json", output / "frozen-plan.json")
    assert frozen.captures[0].capture_sha256 == sha256(RAW).hexdigest()
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())
    with pytest.raises(ValueError, match="exists"):
        prepare(original, output, RULE, start=START, end=END, environment="lab")
    assert (output / "Security.evtx").read_bytes() == RAW


def test_matching_windows_collection_metadata_remains_unknown_not_certified_benign(tmp_path):
    original = source(tmp_path)
    output = tmp_path / "prepared"
    plan = prepare(original, output, RULE, collection_info=metadata(tmp_path))
    (entry,) = plan.captures
    assert entry.capture_id == "auth-window" and entry.environment == "private lab"
    assert entry.label == "unlabeled" and entry.reviewer is None
    assert entry.label_reference == "collection.json"
    assert json.loads((output / "collection.json").read_text())["record_count"] == 7
    assert "private-host" not in (output / "review-notes.md").read_text()


@pytest.mark.parametrize(
    "updates",
    [
        {"capture_sha256": "0" * 64},
        {"bytes": len(RAW) + 1},
        {"record_count": 0},
        {"record_count": 10001},
        {"channel": "System"},
        {"exported_at": "2019-01-01T00:00:00Z"},
        {"collection_end": START},
        {"collection_start": "2020-01-01T00:00:00"},
    ],
)
def test_inconsistent_collection_metadata_is_rejected_without_output(tmp_path, updates):
    original = source(tmp_path)
    output = tmp_path / "prepared"
    with pytest.raises(ValueError):
        prepare(original, output, RULE, collection_info=metadata(tmp_path, **updates))
    assert not output.exists()


@pytest.mark.parametrize(
    "updates",
    [
        {"start": START},
        {"end": END},
        {"environment": "override"},
        {"capture_id": "override"},
    ],
)
def test_metadata_cannot_be_silently_overridden(tmp_path, updates):
    with pytest.raises(ValueError, match="overridden"):
        prepare(
            source(tmp_path),
            tmp_path / "prepared",
            RULE,
            collection_info=metadata(tmp_path),
            **updates,
        )


@pytest.mark.parametrize("raw", [b"", b"not EVTX", b"ElfFile\0" + b"x" * 5_000_000])
def test_empty_invalid_header_or_oversize_input_is_rejected(tmp_path, raw):
    with pytest.raises(ValueError, match="size or header"):
        prepare(
            source(tmp_path, raw),
            tmp_path / "prepared",
            RULE,
            start=START,
            end=END,
            environment="lab",
        )
    assert not (tmp_path / "prepared").exists()


@pytest.mark.parametrize(
    "updates",
    [
        {"start": None},
        {"end": None},
        {"environment": None},
        {"start": "2020-01-01T00:00:00"},
        {"end": START},
        {"environment": " "},
        {"capture_id": "../escape"},
    ],
)
def test_manual_preparation_requires_explicit_consistent_inputs(tmp_path, updates):
    args = {"start": START, "end": END, "environment": "lab", **updates}
    with pytest.raises(ValueError):
        prepare(source(tmp_path), tmp_path / "prepared", RULE, **args)
    assert not (tmp_path / "prepared").exists()
