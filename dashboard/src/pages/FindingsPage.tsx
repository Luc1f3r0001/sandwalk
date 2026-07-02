import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams, Link } from "react-router-dom";
import { Download, Laptop, GitBranch } from "lucide-react";
import { api } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { SourceBadge } from "../components/SourceBadge";
import { FindingDetailModal } from "../components/FindingDetailModal";
import type { Finding } from "../types";
import { formatDistanceToNow } from "date-fns";

function PassCell({ pid, has }: { pid: string; has: boolean | null }) {
  if (pid !== "ssh_private_key") return <span style={{ color: "var(--text-dim)" }}>—</span>;
  if (has === false) return <span className="font-mono text-[10px]" style={{ color: "var(--red)" }}>🔓 NONE</span>;
  if (has === true)  return <span className="font-mono text-[10px]" style={{ color: "var(--green)" }}>🔒 SET</span>;
  return <span style={{ color: "var(--text-dim)" }}>—</span>;
}

const Select = ({ label, value, onChange, opts }: { label: string; value: string; onChange: (v: string) => void; opts: string[] }) => (
  <div className="flex items-center gap-2">
    <label className="font-mono text-[9px] tracking-wider" style={{ color: "var(--text-3)" }}>{label}</label>
    <select value={value} onChange={e => onChange(e.target.value)}
      className="rounded px-2 py-1 text-xs font-mono focus:outline-none"
      style={{ background: "var(--bg)", color: "var(--text-2)", border: "1px solid #1e3a5f" }}>
      {opts.map(s => <option key={s} value={s} style={{ background: "var(--bg)" }}>{s || "ALL"}</option>)}
    </select>
  </div>
);

export function FindingsPage() {
  const [sp] = useSearchParams();
  const [sev, setSev]   = useState(sp.get("severity") || "");
  const [stat, setStat] = useState("open");
  const [cat, setCat]   = useState(sp.get("category") || "");
  const [src, setSrc]   = useState(sp.get("source") || "");
  const [sel, setSel]   = useState<Finding | null>(null);

  useEffect(() => { setSev(sp.get("severity")||""); setCat(sp.get("category")||""); setSrc(sp.get("source")||""); }, [sp]);

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", sev, stat, cat, src],
    queryFn: () => api.getFindings({ severity: sev||undefined, status: stat||undefined, category: cat||undefined, source_type: src||undefined, limit: 500 }),
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="font-mono text-xs tracking-widest mb-1" style={{ color: "var(--text-2)" }}>FINDINGS DATABASE</div>
          <h1 className="text-xl font-bold" style={{ color: "var(--text)" }}>All Findings</h1>
          <p className="text-xs mt-1" style={{ color: "var(--text-3)" }}>{findings?.length ?? 0} findings</p>
        </div>
        <div className="flex gap-2">
          <a href={api.exportCsvUrl(stat||"open")} className="flex items-center gap-1.5 px-3 py-1.5 rounded font-mono text-[10px] tracking-wider" style={{ background: "var(--bg)", color: "var(--text-3)", border: "1px solid #1e3a5f", textDecoration: "none" }}>
            <Download className="w-3.5 h-3.5" /> CSV
          </a>
        </div>
      </div>

      {/* Source tabs */}
      <div className="flex items-center gap-2">
        {[{v:"",l:"ALL SOURCES"},{v:"machine",l:"FILESYSTEM",icon:<Laptop className="w-3 h-3"/>},{v:"git",l:"GIT HISTORY",icon:<GitBranch className="w-3 h-3"/>}].map(({v,l,icon}) => (
          <button key={v} onClick={() => setSrc(v)} className="flex items-center gap-1.5 px-3 py-1.5 rounded font-mono text-[9px] tracking-wider transition-all"
            style={{ background: src===v ? (v==="git"?"var(--purple-bg)":"var(--bg-row)") : "transparent", color: src===v ? (v==="git"?"var(--purple)":"var(--text-2)") : "var(--text-3)", border: `1px solid ${src===v?(v==="git"?"var(--purple-bd)":"var(--text-dim)"):"var(--border)"}` }}>
            {icon}{l}
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="rounded-lg p-4 flex flex-wrap items-center gap-4" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
        <Select label="SEVERITY" value={sev}  onChange={setSev}  opts={["","critical","high","medium","low"]} />
        <Select label="STATUS"   value={stat} onChange={setStat} opts={["open","removed_active","rotated","fixed",""]} />
        <Select label="CATEGORY" value={cat}  onChange={setCat}  opts={["","cloud","vcs","payment","database","saas","ai","crypto","auth","generic"]} />
      </div>

      {/* Table */}
      <div className="rounded-lg overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
        {isLoading ? (
          <div className="py-16 text-center font-mono text-xs tracking-widest" style={{ color: "var(--text-dim)" }}>SCANNING...</div>
        ) : (findings?.length ?? 0) > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: "1px solid #1a2a45", background: "var(--bg)" }}>
                  {["SEV","SRC","TYPE","MACHINE","FILE","SECRET HINT","ACTIVE","PASSPHRASE","STATUS","FOUND"].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left font-mono tracking-widest" style={{ color: "var(--text-dim)", fontSize: 9 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings!.map(f => (
                  <tr key={f.id} className="cursor-pointer transition-colors" style={{ borderBottom: "1px solid #0f1629" }}
                    onClick={() => setSel(f)}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-row)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                    <td className="px-4 py-2.5"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-2.5"><SourceBadge source={f.source_type} /></td>
                    <td className="px-4 py-2.5 max-w-[140px] truncate font-medium" style={{ color: "var(--text-2)" }}>{f.pattern_name}</td>
                    <td className="px-4 py-2.5">
                      <Link to={`/machines/${f.machine_id}`} onClick={e => e.stopPropagation()} style={{ color: "var(--text-2)", textDecoration: "none", fontWeight: 500 }}>{f.hostname}</Link>
                      <div className="font-mono text-[10px]" style={{ color: "var(--text-3)" }}>{f.username}</div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px] max-w-[160px] truncate" style={{ color: "var(--text-3)" }}>
                      {f.file_path.replace(/^\/Users\/[^/]+/, "~")}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px]" style={{ color: "var(--amber)" }}>{f.value_preview}</td>
                    <td className="px-4 py-2.5 font-mono text-[10px] font-bold">
                      {f.verified_active === true  && <span style={{ color: "var(--red)" }}>LIVE</span>}
                      {f.verified_active === false && <span style={{ color: "var(--green)" }}>DEAD</span>}
                      {f.verified_active === null  && <span style={{ color: "var(--text-dim)" }}>—</span>}
                    </td>
                    <td className="px-4 py-2.5"><PassCell pid={f.pattern_id} has={f.ssh_has_passphrase} /></td>
                    <td className="px-4 py-2.5"><StatusBadge status={f.status} /></td>
                    <td className="px-4 py-2.5 font-mono text-[10px]" style={{ color: "var(--text-3)" }}>
                      {formatDistanceToNow(new Date(f.first_seen), { addSuffix: true })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center">
            <div className="font-mono text-xs tracking-widest" style={{ color: "var(--text-dim)" }}>NO FINDINGS</div>
          </div>
        )}
      </div>
      {sel && <FindingDetailModal finding={sel} onClose={() => setSel(null)} />}
    </div>
  );
}
