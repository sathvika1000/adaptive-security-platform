"""Normalize EVTX XML while retaining unsupported records and original evidence."""

from importlib import import_module

from adaptive_security.connectors.otrf import normalize as normalize_flat
from adaptive_security.domain.events import SecurityEvent

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def normalize(xml: str, *, capture_sha256: str, member: str, ordinal: int) -> SecurityEvent:
    try:
        parser = import_module("defusedxml.ElementTree")
    except ImportError:
        raise ValueError("EVTX import requires the optional evtx dependencies") from None
    try:
        root = parser.fromstring(xml, forbid_dtd=True)
        system = root.find("e:System", NS)
        if system is None:
            raise ValueError("missing system")
        provider = system.find("e:Provider", NS)
        time = system.find("e:TimeCreated", NS)
        if provider is None or time is None:
            raise ValueError("missing provider or timestamp")
        stamp = time.attrib["SystemTime"]
        event_id = int(system.findtext("e:EventID", namespaces=NS))
        channel = system.findtext("e:Channel", namespaces=NS)
        computer = system.findtext("e:Computer", namespaces=NS)
        record_id = system.findtext("e:EventRecordID", namespaces=NS)
        fields = {}
        for data in root.findall("e:EventData/e:Data", NS):
            name = data.attrib["Name"]
            if name in fields:
                raise ValueError("duplicate field")
            fields[name] = data.text
        # Apply existing Windows mappings only to the actual Security audit provider.
        mapped_channel = channel if provider.attrib.get("Name") == (
            "Microsoft-Windows-Security-Auditing") else "unmapped-provider"
        raw = {**fields, "Channel": mapped_channel, "EventID": event_id,
               "EventTime": stamp, "@timestamp": stamp, "Hostname": computer}
        event = normalize_flat(raw, capture_sha256=capture_sha256, member=member,
                               line=ordinal, timezone="UTC")
    except Exception:
        raise ValueError(f"invalid EVTX XML at record {ordinal}") from None
    return event.model_copy(update={"source": "evtx", "attributes": {
        **event.attributes, "channel": channel, "provider": provider.attrib.get("Name"),
        "evtx_record_id": record_id, "raw_xml": xml,
        "observation_time_basis": "unavailable; fallback to SystemTime event time",
    }})
