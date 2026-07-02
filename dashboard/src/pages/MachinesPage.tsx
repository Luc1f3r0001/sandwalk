import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Monitor, Clock } from "lucide-react";
import { api } from "../api/client";
import { FdaBadge } from "../components/FdaBadge";
import { RescanButton } from "../components/RescanButton";
import { formatDistanceToNow } from "date-fns";

export function MachinesPage() {
  const navigate = useNavigate();
  const { data: machines, isLoading } = useQuery({ queryKey: ["machines"], queryFn: api.getMachines, refetchInterval: 30_000 });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="font-mono text-xs tracking-widest mb-1" style={{ color: "var(--text-2)" }}>ENDPOINT REGISTRY</div>
          <h1 className="text-xl font-bold" style={{ color: "var(--text)" }}>All Machines</h1>
        </div>
        <span className="font-mono text-xs px-3 py-1.5 rounded" style={{ background: "var(--bg-row)", color: "var(--text-2)", border: "1px solid #1e3a5f" }}>
          {machines?.length ?? 0} endpoints
        </span>
      </div>

      <div className="rounded-lg overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
        <div className="px-5 py-3" style={{ background: "var(--bg)", borderBottom: "1px solid #1a2a45" }}>
          <span className="font-mono text-[9px] tracking-widest" style={{ color: "var(--text-dim)" }}>HOSTNAME · VERSION · FDA · RISK · LAST SEEN</span>
        </div>
        {isLoading ? (
          <div className="py-12 text-center font-mono text-xs tracking-widest" style={{ color: "var(--text-dim)" }}>LOADING...</div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: "1px solid #1a2a45" }}>
                {["ENDPOINT","OS","VERSION","FDA","CRIT","HIGH","MED","TOTAL","LAST SEEN",""].map(h => (
                  <th key={h} className="px-4 py-2.5 text-left font-mono tracking-widest" style={{ color: "var(--text-dim)", fontSize: 9 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {machines?.map(m => (
                <tr key={m.id} className="cursor-pointer transition-colors" style={{ borderBottom: "1px solid #0f1629" }}
                  onClick={() => navigate(`/machines/${m.id}`)}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-row)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Monitor className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "var(--text-2)" }} />
                      <div>
                        <div className="font-medium" style={{ color: "var(--text)" }}>{m.hostname}</div>
                        <div className="font-mono text-[10px]" style={{ color: "var(--text-3)" }}>{m.username}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono capitalize" style={{ color: "var(--text-3)" }}>{m.os}</td>
                  <td className="px-4 py-3 font-mono" style={{ color: "var(--text-3)" }}>v{m.agent_version ?? "—"}</td>
                  <td className="px-4 py-3"><FdaBadge granted={m.fda_granted} compact /></td>
                  <td className="px-4 py-3 font-mono font-bold text-center" style={{ color: m.open_critical > 0 ? "var(--red)" : "var(--text-dim)" }}>
                    {m.open_critical > 0 ? m.open_critical : "—"}
                  </td>
                  <td className="px-4 py-3 font-mono font-bold text-center" style={{ color: m.open_high > 0 ? "var(--orange)" : "var(--text-dim)" }}>
                    {m.open_high > 0 ? m.open_high : "—"}
                  </td>
                  <td className="px-4 py-3 font-mono text-center" style={{ color: m.open_medium > 0 ? "var(--amber)" : "var(--text-dim)" }}>
                    {m.open_medium > 0 ? m.open_medium : "—"}
                  </td>
                  <td className="px-4 py-3 font-mono font-bold text-center" style={{ color: "var(--text-2)" }}>{m.total_open}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1 font-mono text-[10px]" style={{ color: "var(--text-3)" }}>
                      <Clock className="w-3 h-3" />{formatDistanceToNow(new Date(m.last_seen), { addSuffix: true })}
                    </div>
                  </td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <RescanButton machineId={m.id} size="sm" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
