import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { X, Key, AlertTriangle, Lock } from "lucide-react";
import { api } from "../api/client";
import type { Finding, FindingStatus } from "../types";
import { SeverityBadge } from "./SeverityBadge";
import { StatusBadge } from "./StatusBadge";

export function FindingDetailModal({ finding: f, onClose }: { finding: Finding; onClose: () => void }) {
  const qc = useQueryClient();
  const [msg, setMsg] = useState<string|null>(null);
  const [verifying, setVerifying] = useState(false);
  const [notes, setNotes] = useState(f.notes ?? "");

  const mutation = useMutation({
    mutationFn: ({ status, n }: { status: FindingStatus; n: string }) => api.updateFinding(f.id, status, n),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); onClose(); }
  });

  const handleReverify = async () => {
    setVerifying(true); setMsg(null);
    try { const r = await api.reverifyFinding(f.id); setMsg(r.message); qc.invalidateQueries({ queryKey: ["findings"] }); }
    catch { setMsg("Dispatch failed"); }
    finally { setVerifying(false); }
  };

  const Row = ({ label, children }: { label: string; children: React.ReactNode }) => (
    <div className="flex gap-3 py-2" style={{ borderBottom: "1px solid #0f1629" }}>
      <span className="font-mono text-[9px] tracking-wider w-28 flex-shrink-0 pt-0.5" style={{ color: "var(--text-3)" }}>{label}</span>
      <div className="text-xs" style={{ color: "var(--text-2)" }}>{children}</div>
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.8)" }} onClick={onClose}>
      <div className="rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" style={{ background: "var(--bg-card)", border: "1px solid #1e3a5f" }} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: "1px solid #1a2a45", background: "var(--bg)" }}>
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" style={{ color: "var(--red)" }} />
            <span className="font-mono text-xs tracking-widest" style={{ color: "var(--text)" }}>FINDING DETAIL</span>
            <SeverityBadge severity={f.severity} />
            <StatusBadge status={f.status} />
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)" }}><X className="w-4 h-4" /></button>
        </div>
        <div className="px-5 py-4 space-y-4">
          <div className="rounded-lg p-4" style={{ background: "var(--bg)", border: "1px solid #2a1a00" }}>
            <div className="flex items-center gap-2 mb-2">
              <Key className="w-3.5 h-3.5" style={{ color: "var(--amber)" }} />
              <span className="font-mono text-[9px] tracking-widest" style={{ color: "var(--amber)" }}>REDACTED HINT</span>
            </div>
            <div className="font-mono text-sm" style={{ color: "var(--amber)" }}>{f.value_preview}</div>
            <div className="text-[10px] mt-2" style={{ color: "var(--text-3)" }}>Plaintext never stored centrally. Use "Re-validate on device" to check liveness.</div>
          </div>
          {f.pattern_id === "ssh_private_key" && f.ssh_has_passphrase === false && (
            <div className="rounded-lg p-3 flex items-center gap-2" style={{ background: "var(--red-bg)", border: "1px solid #5a1a1a" }}>
              <Lock className="w-4 h-4 flex-shrink-0" style={{ color: "var(--red)" }} />
              <div className="font-mono text-[11px]" style={{ color: "var(--red)" }}>🔓 NO PASSPHRASE — key is immediately usable if leaked</div>
            </div>
          )}
          <div>
            <Row label="TYPE">{f.pattern_name}</Row>
            <Row label="MACHINE"><span>{f.hostname} <span style={{ color: "var(--text-3)" }}>({f.username})</span></span></Row>
            <Row label="FILE"><span className="font-mono text-[11px] break-all" style={{ color: "var(--text-3)" }}>{f.file_path}</span></Row>
            <Row label="SOURCE">{f.source_type === "git" ? "Git history" : "Filesystem"}</Row>
            <Row label="ACTIVE">
              {f.verified_active === true  ? <span className="font-mono font-bold" style={{ color: "var(--red)" }}>LIVE — ROTATE NOW</span>
              : f.verified_active === false ? <span className="font-mono" style={{ color: "var(--green)" }}>Inactive</span>
              : <span style={{ color: "var(--text-3)" }}>Unknown</span>}
            </Row>
            {f.pattern_id === "ssh_private_key" && (
              <Row label="PASSPHRASE">
                {f.ssh_has_passphrase === false ? <span className="font-mono" style={{ color: "var(--red)" }}>🔓 Not set</span>
                : f.ssh_has_passphrase === true  ? <span className="font-mono" style={{ color: "var(--green)" }}>🔒 Protected</span>
                : <span style={{ color: "var(--text-3)" }}>Unknown</span>}
              </Row>
            )}
            <Row label="FIRST SEEN">{new Date(f.first_seen).toLocaleString()}</Row>
            <Row label="LAST SEEN">{new Date(f.last_seen).toLocaleString()}</Row>
          </div>
          <div>
            <label className="font-mono text-[9px] tracking-widest block mb-1.5" style={{ color: "var(--text-3)" }}>NOTES</label>
            <textarea value={notes} onChange={e => setNotes(e.target.value)} rows={2}
              className="w-full px-3 py-2 rounded text-xs font-mono resize-none focus:outline-none"
              style={{ background: "var(--bg)", color: "var(--text-2)", border: "1px solid #1e3a5f" }}
              placeholder="Add investigation notes..."
              onFocus={e => (e.target.style.borderColor = "var(--text-2)")}
              onBlur={e => (e.target.style.borderColor = "var(--text-dim)")} />
          </div>
          {msg && <div className="rounded px-3 py-2 font-mono text-[11px]" style={{ background: "var(--bg-row)", color: "var(--text-2)", border: "1px solid #1e3a5f" }}>{msg}</div>}
        </div>
        <div className="flex items-center gap-2 px-5 py-4" style={{ borderTop: "1px solid #1a2a45", background: "var(--bg)" }}>
          <button onClick={handleReverify} disabled={verifying}
            className="flex items-center gap-1.5 px-3 py-2 rounded font-mono text-[10px] tracking-wide transition-all disabled:opacity-50"
            style={{ background: "var(--purple-bg)", color: "var(--purple)", border: "1px solid #3b1a6f" }}>
            {verifying ? "DISPATCHING..." : "RE-VALIDATE ON DEVICE"}
          </button>
          <div className="flex-1" />
          <button onClick={onClose} className="px-3 py-2 rounded font-mono text-[10px] tracking-wide" style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)" }}>CLOSE</button>
          <button onClick={() => mutation.mutate({ status: "fixed", n: notes })}
            className="px-3 py-2 rounded font-mono text-[10px] tracking-wide"
            style={{ background: "var(--green-bg)", color: "var(--green)", border: "1px solid #1a4020", cursor: "pointer" }}>
            MARK FIXED
          </button>
        </div>
      </div>
    </div>
  );
}
