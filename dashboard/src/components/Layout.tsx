import { Link, useLocation } from "react-router-dom";
import { Shield, Laptop, AlertTriangle, Download, LogOut, Activity, ChevronRight, Sun, Moon } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useTheme } from "../App";

declare const __DASHBOARD_VERSION__: string;

const NAV = [
  { label: "Monitor", items: [
    { to: "/",         label: "Dashboard",    icon: Activity,      exact: true  },
    { to: "/findings", label: "All Findings", icon: AlertTriangle, exact: false },
  ]},
  { label: "Fleet", items: [
    { to: "/machines", label: "Machines",     icon: Laptop,        exact: false },
  ]},
];

export function Layout({ children, onLogout }: { children: React.ReactNode; onLogout?: () => void }) {
  const { pathname } = useLocation();
  const { theme, toggle } = useTheme();
  const { data: stats } = useQuery({ queryKey: ["stats"], queryFn: api.getStats, refetchInterval: 30_000 });

  const pageTitle = pathname === "/" ? "Dashboard"
    : pathname === "/findings" ? "All Findings"
    : pathname === "/machines" ? "Machines"
    : pathname.startsWith("/machines/") ? "Machine Detail"
    : "Sandwalk";

  const badge = (to: string) =>
    to === "/findings" ? stats?.open_findings ?? null
    : to === "/machines" ? stats?.total_machines ?? null
    : null;

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "var(--bg)" }}>

      {/* Sidebar */}
      <aside className="flex flex-col flex-shrink-0"
        style={{ width: 210, background: "var(--sidebar)", borderRight: "1px solid var(--border)" }}>

        {/* Brand */}
        <Link to="/" className="flex items-center gap-2.5 px-4 py-4 select-none flex-shrink-0"
          style={{ borderBottom: "1px solid var(--border)", textDecoration: "none" }}>
          <div className="flex items-center justify-center w-7 h-7 rounded"
            style={{ background: "var(--bg-row)", border: "1px solid var(--border-hi)" }}>
            <Shield className="w-3.5 h-3.5" style={{ color: "var(--red)" }} />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", letterSpacing: "-0.01em" }}>Sandwalk</div>
            <div style={{ fontSize: 10, color: "var(--text-3)", marginTop: 1 }}>Secrets scanner</div>
          </div>
        </Link>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3 px-2" style={{ scrollbarWidth: "none" }}>
          {NAV.map(group => (
            <div key={group.label} className="mb-4">
              <div className="px-2 mb-1" style={{ fontSize: 10, fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                {group.label}
              </div>
              {group.items.map(({ to, label, icon: Icon, exact }) => {
                const active = exact ? pathname === to : pathname.startsWith(to);
                const b = badge(to);
                return (
                  <Link key={to} to={to}
                    className="flex items-center gap-2.5 px-2 py-2 rounded mb-0.5 text-sm font-medium transition-colors"
                    style={{
                      color: active ? "var(--text)" : "var(--text-3)",
                      background: active ? "var(--accent-bg)" : "transparent",
                      textDecoration: "none",
                    }}
                    onMouseEnter={e => !active && (e.currentTarget.style.color = "var(--text-2)")}
                    onMouseLeave={e => !active && (e.currentTarget.style.color = "var(--text-3)")}>
                    <Icon className="w-3.5 h-3.5 flex-shrink-0" />
                    <span className="flex-1">{label}</span>
                    {b !== null && b > 0 && (
                      <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-3)", background: "var(--bg-row)", padding: "1px 6px", borderRadius: 8 }}>
                        {b}
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>
          ))}

          <div className="mb-4">
            <div className="px-2 mb-1" style={{ fontSize: 10, fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>Export</div>
            {[{ href: api.exportCsvUrl("open"), label: "Export CSV" }, { href: api.exportSarifUrl(), label: "Export SARIF" }].map(({ href, label }) => (
              <a key={label} href={href}
                className="flex items-center gap-2.5 px-2 py-2 rounded mb-0.5 text-sm transition-colors"
                style={{ color: "var(--text-3)", textDecoration: "none" }}
                onMouseEnter={e => (e.currentTarget.style.color = "var(--text-2)")}
                onMouseLeave={e => (e.currentTarget.style.color = "var(--text-3)")}>
                <Download className="w-3.5 h-3.5 flex-shrink-0" />
                {label}
              </a>
            ))}
          </div>
        </nav>

        {/* Footer */}
        <div className="px-3 py-3 flex items-center justify-between flex-shrink-0"
          style={{ borderTop: "1px solid var(--border)" }}>
          <span style={{ fontSize: 11, color: "var(--text-dim)" }}>v{__DASHBOARD_VERSION__}</span>
          <div className="flex items-center gap-1">
            <button onClick={toggle} title={theme === "dark" ? "Light mode" : "Dark mode"}
              className="flex items-center justify-center w-6 h-6 rounded transition-colors"
              style={{ background: "var(--bg-row)", border: "1px solid var(--border)", cursor: "pointer", color: "var(--text-3)" }}
              onMouseEnter={e => (e.currentTarget.style.color = "var(--text)")}
              onMouseLeave={e => (e.currentTarget.style.color = "var(--text-3)")}>
              {theme === "dark" ? <Sun className="w-3 h-3" /> : <Moon className="w-3 h-3" />}
            </button>
            {onLogout && (
              <button onClick={onLogout} title="Sign out"
                className="flex items-center justify-center w-6 h-6 rounded transition-colors"
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)" }}
                onMouseEnter={e => (e.currentTarget.style.color = "var(--red)")}
                onMouseLeave={e => (e.currentTarget.style.color = "var(--text-3)")}>
                <LogOut className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex flex-col flex-1 overflow-hidden min-w-0">
        <header className="flex items-center justify-between px-6 flex-shrink-0"
          style={{ height: 52, background: "var(--topbar)", borderBottom: "1px solid var(--border)" }}>
          <div className="flex items-center gap-2">
            {pathname !== "/" && (
              <>
                <Link to="/" style={{ fontSize: 13, color: "var(--text-3)", textDecoration: "none" }}
                  onMouseEnter={e => (e.currentTarget.style.color = "var(--text-2)")}
                  onMouseLeave={e => (e.currentTarget.style.color = "var(--text-3)")}>
                  Dashboard
                </Link>
                <ChevronRight className="w-3.5 h-3.5" style={{ color: "var(--text-dim)" }} />
              </>
            )}
            <span style={{ fontSize: 14, fontWeight: 600, color: "var(--text)" }}>{pageTitle}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ background: "var(--green)" }} />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5" style={{ background: "var(--green)" }} />
            </span>
            <span style={{ fontSize: 11, color: "var(--text-3)" }}>Live</span>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
