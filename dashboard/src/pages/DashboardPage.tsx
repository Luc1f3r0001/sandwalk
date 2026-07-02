import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Laptop, GitBranch, ChevronRight } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { StatsCard } from "../components/StatsCard";
import { FdaBadge } from "../components/FdaBadge";
import { formatDistanceToNow } from "date-fns";

function LivePulse() {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
      </span>
      <span className="font-mono text-[10px] tracking-widest" style={{ color: "var(--green)" }}>LIVE</span>
    </span>
  );
}

export function DashboardPage() {
  const navigate = useNavigate();
  const { data: stats, isLoading } = useQuery({ queryKey: ["stats"], queryFn: api.getStats, refetchInterval: 30_000 });
  const { data: machines } = useQuery({ queryKey: ["machines"], queryFn: api.getMachines, refetchInterval: 30_000 });

  if (isLoading) return (
    <div className="flex items-center justify-center h-64">
      <div className="font-mono text-xs tracking-widest" style={{ color: "var(--text-dim)" }}>LOADING<span className="blink">_</span></div>
    </div>
  );

  const topMachines = [...(machines ?? [])].sort((a, b) => b.open_critical - a.open_critical || b.open_high - a.open_high);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-xs tracking-widest" style={{ color: "var(--text-2)" }}>SECURITY DASHBOARD</span>
            <span style={{ color: "var(--text-dim)" }}>·</span>
            <LivePulse />
          </div>
          <h1 className="text-xl font-bold" style={{ color: "var(--text)" }}>Fleet Credential Exposure</h1>
        </div>
        <div className="text-right">
          <div className="font-mono text-[10px]" style={{ color: "var(--text-dim)" }}>{new Date().toISOString().slice(0,19).replace("T"," ")} UTC</div>
          <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{machines?.length ?? 0} endpoints monitored</div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatsCard label="MACHINES"     value={stats?.total_machines ?? 0}    sub={`${stats?.scanned_last_7d ?? 0} active this week`} color="default"   to="/machines" />
        <StatsCard label="CRITICAL"     value={stats?.critical_findings ?? 0}  sub="Immediate action"     color={stats?.critical_findings ? "red" : "default"}    to="/findings?severity=critical" />
        <StatsCard label="HIGH"         value={stats?.high_findings ?? 0}      sub="72h SLA"              color={stats?.high_findings ? "orange" : "default"}     to="/findings?severity=high" />
        <StatsCard label="MEDIUM"       value={stats?.medium_findings ?? 0}    sub="7 day SLA"                                                                 to="/findings?severity=medium" />
        <StatsCard label="ON MACHINE"   value={stats?.machine_findings ?? 0}   sub="Filesystem secrets"   color="default"                                          to="/findings?source=machine" />
        <StatsCard label="IN GIT"       value={stats?.git_findings ?? 0}       sub="History commits"      color="purple"                                        to="/findings?source=git" />
      </div>

      {/* Charts row */}
      <div className="grid md:grid-cols-2 gap-4">
        {/* Category bars */}
        <div className="rounded-lg p-5" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
          <div className="flex items-center justify-between mb-4">
            <span className="font-mono text-xs tracking-widest" style={{ color: "var(--text-2)" }}>BY CATEGORY</span>
            <Link to="/findings" className="flex items-center gap-1 text-xs transition-colors" style={{ color: "var(--text-dim)", textDecoration: "none" }}
              onMouseEnter={e => (e.currentTarget.style.color = "var(--text-2)")} onMouseLeave={e => (e.currentTarget.style.color = "var(--text-dim)")}>
              view all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          {stats && Object.keys(stats.findings_by_category).length > 0 ? (
            <div className="space-y-3">
              {Object.entries(stats.findings_by_category).sort(([,a],[,b]) => b-a).map(([cat, count]) => {
                const max = Math.max(...Object.values(stats.findings_by_category));
                return (
                  <Link key={cat} to={`/findings?category=${cat}`} className="flex items-center gap-3 group" style={{ textDecoration: "none" }}>
                    <span className="font-mono text-xs w-20 flex-shrink-0 capitalize" style={{ color: "#8b9dc3" }}>{cat}</span>
                    <div className="flex-1 rounded-full h-1.5" style={{ background: "var(--border)" }}>
                      <div className="h-1.5 rounded-full" style={{ width: `${Math.round((count/max)*100)}%`, background: "linear-gradient(90deg, var(--text-3), var(--red))" }} />
                    </div>
                    <span className="font-mono text-xs font-bold w-8 text-right" style={{ color: "var(--text)" }}>{count}</span>
                  </Link>
                );
              })}
            </div>
          ) : <p className="text-xs font-mono" style={{ color: "var(--text-dim)" }}>NO OPEN FINDINGS</p>}
        </div>

        {/* Top types */}
        <div className="rounded-lg p-5" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
          <span className="font-mono text-xs tracking-widest" style={{ color: "var(--text-2)" }}>TOP CREDENTIAL TYPES</span>
          <div className="mt-4 space-y-0.5">
            {stats?.top_finding_types?.slice(0,8).map((t, i) => (
              <Link key={t.name} to="/findings"
                className="flex items-center justify-between py-2 px-2 rounded text-xs transition-colors"
                style={{ textDecoration: "none", color: "inherit", borderBottom: "1px solid #0f1629" }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-row)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px]" style={{ color: "var(--text-dim)" }}>{String(i+1).padStart(2,"0")}</span>
                  <span style={{ color: "var(--text-2)" }}>{t.name}</span>
                </div>
                <span className="font-mono text-xs font-bold px-2 py-0.5 rounded" style={{ background: "var(--bg-row)", color: "var(--text-2)" }}>{t.count}</span>
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Machines table */}
      <div className="rounded-lg overflow-hidden" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid #1a2a45", background: "var(--bg)" }}>
          <span className="font-mono text-xs tracking-widest" style={{ color: "var(--text-2)" }}>ENDPOINT STATUS</span>
          <Link to="/machines" className="text-xs flex items-center gap-1" style={{ color: "var(--text-dim)", textDecoration: "none" }}
            onMouseEnter={e => (e.currentTarget.style.color = "var(--text-2)")} onMouseLeave={e => (e.currentTarget.style.color = "var(--text-dim)")}>
            all machines <ChevronRight className="w-3 h-3" />
          </Link>
        </div>
        <table className="w-full text-xs">
          <thead>
            <tr style={{ borderBottom: "1px solid #1a2a45" }}>
              {["ENDPOINT","VERSION","FDA","CRITICAL","HIGH","TOTAL","LAST SEEN"].map(h => (
                <th key={h} className="px-4 py-2.5 text-left font-mono tracking-widest" style={{ color: "var(--text-dim)", fontSize: 9 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {topMachines.map(m => (
              <tr key={m.id} className="cursor-pointer transition-colors" style={{ borderBottom: "1px solid #0f1629" }}
                onClick={() => navigate(`/machines/${m.id}`)}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-row)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                <td className="px-4 py-3">
                  <div className="font-medium" style={{ color: "var(--text)" }}>{m.hostname}</div>
                  <div className="font-mono text-[10px]" style={{ color: "var(--text-3)" }}>{m.username}</div>
                </td>
                <td className="px-4 py-3 font-mono" style={{ color: "var(--text-3)" }}>v{m.agent_version ?? "—"}</td>
                <td className="px-4 py-3"><FdaBadge granted={m.fda_granted} compact /></td>
                <td className="px-4 py-3 font-mono font-bold" style={{ color: m.open_critical > 0 ? "var(--red)" : "var(--text-dim)" }}>
                  {m.open_critical > 0 ? m.open_critical : "—"}
                </td>
                <td className="px-4 py-3 font-mono font-bold" style={{ color: m.open_high > 0 ? "var(--orange)" : "var(--text-dim)" }}>
                  {m.open_high > 0 ? m.open_high : "—"}
                </td>
                <td className="px-4 py-3 font-mono" style={{ color: m.total_open > 0 ? "var(--text-2)" : "var(--text-dim)" }}>{m.total_open}</td>
                <td className="px-4 py-3 font-mono text-[10px]" style={{ color: "var(--text-3)" }}>
                  {formatDistanceToNow(new Date(m.last_seen), { addSuffix: true })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
