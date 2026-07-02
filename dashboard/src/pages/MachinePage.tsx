import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { api } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { SourceBadge } from "../components/SourceBadge";
import { FdaBadge } from "../components/FdaBadge";
import { RescanButton } from "../components/RescanButton";
import { ValidateAllButton } from "../components/ValidateAllButton";
import { FindingDetailModal } from "../components/FindingDetailModal";
import type { Finding } from "../types";
import { formatDistanceToNow } from "date-fns";

function PassCell({ pid, has }: { pid: string; has: boolean | null }) {
  if (pid !== "ssh_private_key") return <span style={{ color: "var(--text-dim)" }}>—</span>;
  if (has === false) return <span className="font-mono text-[10px]" style={{ color: "var(--red)" }}>🔓 NONE</span>;
  if (has === true)  return <span className="font-mono text-[10px]" style={{ color: "var(--green)" }}>🔒 SET</span>;
  return <span style={{ color: "var(--text-dim)" }}>—</span>;
}

const SFILTS = ["open","removed_active","rotated","fixed",""];
const SEVFILTS = ["","critical","high","medium","low"];

export function MachinePage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [sf, setSf] = useState("open");
  const [sevf, setSevf] = useState("");
  const [sel, setSel] = useState<Finding | null>(null);

  const { data: md } = useQuery({ queryKey: ["machine", id], queryFn: () => api.getMachine(id!), refetchInterval: 30_000 });
  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", id, sf, sevf],
    queryFn: () => api.getFindings({ machine_id: id, status: sf||undefined, severity: sevf||undefined, limit: 500 }),
    refetchInterval: 30_000,
  });

  const m = md?.machine;
  if (!m) return <div className="py-24 text-center font-mono text-xs tracking-widest" style={{ color: "var(--text-dim)" }}>LOADING...</div>;
  const mx = md?.machine as any;

  return (
    <div className="space-y-4">
      <button onClick={() => navigate("/machines")} className="flex items-center gap-1.5 font-mono text-xs transition-colors" style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)" }}
        onMouseEnter={e => (e.currentTarget.style.color = "var(--text-2)")} onMouseLeave={e => (e.currentTarget.style.color = "var(--text-3)")}>
        <ArrowLeft className="w-3.5 h-3.5" /> Machines
      </button>

      {/* Machine card */}
      <div className="rounded-lg p-5" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-lg font-bold" style={{ color: "var(--text)" }}>{m.hostname}</h1>
            <div className="font-mono text-xs mt-1" style={{ color: "var(--text-3)" }}>{m.username} · {m.os} · v{m.agent_version}</div>
          </div>
          <div className="flex items-center gap-2">
            <FdaBadge granted={m.fda_granted} />
            <RescanButton machineId={m.id} />
            <ValidateAllButton machineId={m.id} />
          </div>
        </div>
        <div className="grid grid-cols-4 gap-4 mt-5 pt-5" style={{ borderTop: "1px solid #1a2a45" }}>
          {[
            { label: "OPEN",          value: mx?.open_findings ?? m.total_open, color: "var(--text)" },
            { label: "ACTIVE",        value: mx?.confirmed_active ?? 0,          color: "var(--red)" },
            { label: "REMOVED·LIVE",  value: mx?.removed_active ?? 0,            color: "var(--purple)" },
            { label: "AGENT",         value: `v${m.agent_version ?? "—"}`,       color: "var(--text-2)" },
          ].map(({ label, value, color }) => (
            <div key={label}>
              <div className="font-mono text-[9px] tracking-widest mb-1" style={{ color: "var(--text-dim)" }}>{label}</div>
              <div className="text-2xl font-bold font-mono" style={{ color }}>{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Findings */}
      <div className="rounded-lg overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
        <div className="px-5 py-3 flex flex-wrap items-center gap-3" style={{ borderBottom: "1px solid #1a2a45", background: "var(--bg)" }}>
          <div className="flex gap-1">
            {SFILTS.map(s => (
              <button key={s} onClick={() => setSf(s)} className="px-2.5 py-1 rounded font-mono text-[9px] tracking-wide transition-all"
                style={{ background: sf===s?"var(--bg-row)":"transparent", color: sf===s?"var(--text-2)":"var(--text-3)", border: `1px solid ${sf===s?"var(--text-dim)":"var(--border)"}` }}>
                {s||"ALL"}
              </button>
            ))}
          </div>
          <div className="flex gap-1">
            {SEVFILTS.map(s => (
              <button key={s} onClick={() => setSevf(s)} className="px-2.5 py-1 rounded font-mono text-[9px] tracking-wide transition-all"
                style={{ background: sevf===s&&s?"var(--red-bg)":sevf===s?"var(--bg-row)":"transparent", color: sevf===s?(s?"var(--red)":"var(--text-2)"):"var(--text-3)", border: `1px solid ${sevf===s?(s?"var(--red-bd)":"var(--text-dim)"):"var(--border)"}` }}>
                {s||"ALL SEV"}
              </button>
            ))}
          </div>
        </div>
        {isLoading ? (
          <div className="py-12 text-center font-mono text-xs tracking-widest" style={{ color: "var(--text-dim)" }}>LOADING...</div>
        ) : (findings?.length ?? 0) > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: "1px solid #1a2a45" }}>
                  {["SEV","SRC","TYPE","FILE","HINT","ACTIVE","PASSPHRASE","STATUS","FOUND"].map(h => (
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
                    <td className="px-4 py-2.5 max-w-[140px] truncate" style={{ color: "var(--text-2)" }}>{f.pattern_name}</td>
                    <td className="px-4 py-2.5 font-mono text-[10px] max-w-[180px] truncate" style={{ color: "var(--text-3)" }}>
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
          <div className="py-12 text-center font-mono text-xs tracking-widest" style={{ color: "var(--text-dim)" }}>NO FINDINGS MATCH FILTER</div>
        )}
      </div>
      {sel && <FindingDetailModal finding={sel} onClose={() => setSel(null)} />}
    </div>
  );
}
