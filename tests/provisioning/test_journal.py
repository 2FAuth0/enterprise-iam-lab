from dataclasses import replace
from uuid import uuid4

import pytest

from provisioning.joiner import JoinerEvent
from provisioning.journal import Claim, event_fingerprint
from provisioning.leaver import LeaverEvent
from provisioning.mover import MoverEvent


def test_fingerprint_is_canonical_and_binds_meaningful_fields():
    fields = {
        "event_id": "evt-1", "employee_id": "EMP-1", "username": "synthetic",
        "from_department": "HR", "to_department": "Engineering",
    }
    event = MoverEvent.from_mapping(fields)
    reordered = MoverEvent.from_mapping(dict(reversed(tuple(fields.items()))))
    assert event_fingerprint(event) == event_fingerprint(reordered)
    assert event_fingerprint(event) != event_fingerprint(replace(event, to_department="Finance"))
    assert event_fingerprint(event) != event_fingerprint(LeaverEvent("evt-1", "EMP-1", "synthetic"))


def test_joiner_fingerprint_includes_profile_values():
    event = JoinerEvent(
        "evt-1", "EMP-1", "synthetic", "First", "Last", "synthetic@example.test", "HR", "JOINER",
    )
    assert event_fingerprint(event) != event_fingerprint(replace(event, email="other@example.test"))


def test_rejects_unvalidated_data_and_secret_fields():
    raw = {"event_id": "evt-1", "employee_id": "EMP-1", "username": "synthetic"}
    with pytest.raises(ValueError):
        event_fingerprint({**raw, "client_secret": "never-store"})
    with pytest.raises(ValueError):
        LeaverEvent.from_mapping({**raw, "access_token": "never-store"})
    with pytest.raises(ValueError):
        LeaverEvent.from_mapping({**raw, "employee_id": ""})


def test_claim_token_is_not_in_repr():
    token = uuid4()
    assert str(token) not in repr(Claim("event-1", token))
