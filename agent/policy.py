"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    if context.data_classification not in VALID_CLASSIFICATIONS:
        return False, f"unknown data classification: {context.data_classification!r}"

    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data cannot use egress"

    try:
        principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"principal source unavailable: {exc}"

    principal = principals.get(context.principal_id)
    if principal is None:
        return False, f"unknown principal: {context.principal_id!r}"
    if not context.requested_tool:
        return False, "requested tool is required"
    if context.requested_tool not in principal.get("allowed_tools", []):
        return False, f"principal {context.principal_id} is not allowed to use {context.requested_tool}"
    if context.requested_tool not in context.agent_scopes:
        return False, f"agent scope does not include {context.requested_tool}"
    if context.delegation_depth > 0 and context.requested_tool not in context.parent_scopes:
        return False, f"parent scope does not include {context.requested_tool}"
    if context.request_purpose not in principal.get("purposes", []):
        return False, f"purpose {context.request_purpose!r} is not allowed for {context.principal_id}"
    if not context.expires_at:
        return False, "expires_at is required"
    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return False, "expires_at is not valid ISO-8601"
    if expires_at <= datetime.now(timezone.utc):
        return False, "delegation has expired"
    return True, f"principal {context.principal_id} may use {context.requested_tool}"
