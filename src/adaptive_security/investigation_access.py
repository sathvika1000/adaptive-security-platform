"""Server-owned, content-bound grants for read-only investigation callers."""

import hashlib
import hmac
import re
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from adaptive_security.investigation_tools import ToolFailure, ToolName, ToolRequest
from adaptive_security.offline_review import ReviewSnapshot


class InvestigationGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    capture_id: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(min_length=1, max_length=128)
    review_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    tools: list[ToolName] = Field(min_length=1, max_length=3)


class _IdentityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    key: str = Field(min_length=32, max_length=512)
    grants: list[InvestigationGrant] = Field(min_length=1, max_length=100)


@dataclass(frozen=True)
class InvestigationIdentity:
    actor: str
    digest: str
    grants: tuple[InvestigationGrant, ...]

    def require(self, tool: ToolName, invocation: ToolRequest) -> None:
        if not any(
            grant.capture_id == invocation.capture_id
            and grant.finding_id == invocation.finding_id
            and hmac.compare_digest(grant.review_key, invocation.review_key)
            and tool in grant.tools
            for grant in self.grants
        ):
            raise ToolFailure(403, "Investigation scope or tool is not granted")


def investigation_identities(
    config: object, reserved_digests: set[str],
) -> tuple[InvestigationIdentity, ...]:
    """Validate at startup and retain only key digests; never include input in errors."""
    if not isinstance(config, dict) or len(config) > 32:
        raise ValueError("investigation identities must be an object with at most 32 entries")
    result = []
    seen = set(reserved_digests)
    for actor, entry in config.items():
        if not isinstance(actor, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", actor):
            raise ValueError("invalid investigation identity name")
        try:
            parsed = _IdentityConfig.model_validate(entry)
        except ValueError:
            raise ValueError("invalid investigation identity or grant configuration") from None
        digest = hashlib.sha256(parsed.key.encode("utf-8")).hexdigest()
        if digest in seen:
            raise ValueError("investigation keys must be unique and separate from "
                             "platform/analyst keys")
        seen.add(digest)
        scopes = set()
        for grant in parsed.grants:
            scope = (grant.capture_id, grant.finding_id)
            if scope in scopes or len(set(grant.tools)) != len(grant.tools):
                raise ValueError("duplicate investigation scope or tool")
            scopes.add(scope)
        result.append(InvestigationIdentity(actor, digest, tuple(parsed.grants)))
    return tuple(result)


def authenticate_investigation(
    identities: tuple[InvestigationIdentity, ...], token: str,
) -> InvestigationIdentity:
    provided = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matched = None
    for identity in identities:
        if hmac.compare_digest(provided, identity.digest):
            matched = identity
    if matched is None:
        raise ToolFailure(401, "Unauthorized")
    return matched


class GrantedScope(InvestigationGrant):
    stale: bool


class ScopeCatalog(BaseModel):
    schema_version: int = 1
    actor: str
    matching: int
    next_offset: int | None
    entries: list[GrantedScope]


def scope_catalog(
    snapshot: ReviewSnapshot | None, identity: InvestigationIdentity | None,
    limit: int, offset: int,
) -> ScopeCatalog:
    """Shared discovery projection for authenticated HTTP and local MCP callers."""
    current = snapshot.finding_keys if snapshot is not None else {}
    if identity is None:
        entries = [GrantedScope(
            capture_id=capture_id, finding_id=finding_id, review_key=review_key,
            tools=["get_finding_evidence", "get_related_events", "get_telemetry_coverage"],
            stale=False,
        ) for (capture_id, finding_id), review_key in sorted(current.items())]
    else:
        entries = [GrantedScope(
            **grant.model_dump(),
            stale=current.get((grant.capture_id, grant.finding_id)) != grant.review_key,
        ) for grant in identity.grants]
    selected = entries[offset:offset + limit]
    end = offset + len(selected)
    return ScopeCatalog(
        actor=identity.actor if identity is not None else "platform",
        matching=len(entries), next_offset=end if end < len(entries) else None, entries=selected,
    )
