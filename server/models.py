from pydantic import BaseModel
from typing import Optional


class MachineInfo(BaseModel):
    hostname: str
    username: str
    os: str
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    fda_granted: Optional[bool] = None


class FindingPayload(BaseModel):
    pattern_id: str
    pattern_name: str
    severity: str
    category: str
    source_type: str = "machine"
    file_path: str
    file_paths: Optional[list[str]] = None
    line_number: Optional[int] = None
    value_hash: str
    value_preview: str
    context_line: Optional[str] = None
    verified_active: Optional[bool] = None
    ssh_has_passphrase: Optional[bool] = None
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None


class ScanPayload(BaseModel):
    machine: MachineInfo
    scope: str = "standard"
    scanned_at: str
    duration_ms: Optional[int] = None
    findings: list[FindingPayload]
    drop_hashes: list[str] = []


class FindingUpdate(BaseModel):
    status: str
    notes: Optional[str] = None


class FindingOut(BaseModel):
    id: str
    scan_id: Optional[str] = None
    machine_id: str
    hostname: str
    username: str
    pattern_id: str
    pattern_name: str
    severity: str
    category: str
    source_type: str
    file_path: str
    file_paths: Optional[list[str]] = None
    line_number: Optional[int]
    value_hash: str
    value_preview: str
    context_line: Optional[str]
    verified_active: Optional[bool]
    ssh_has_passphrase: Optional[bool]
    first_seen: str
    last_seen: str
    status: str
    remediated_at: Optional[str]
    notes: Optional[str]
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None
    blast_radius: Optional[str] = None
    remediation: Optional[str] = None


class MachineOut(BaseModel):
    id: str
    hostname: str
    username: str
    os: str
    first_seen: str
    last_seen: str
    scan_count: int
    open_critical: int
    open_high: int
    open_medium: int
    open_low: int
    total_open: int
    agent_version: Optional[str] = None
    fda_granted: Optional[bool] = None
