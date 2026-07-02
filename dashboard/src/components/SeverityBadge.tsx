const CFG: Record<string, { bg: string; text: string; label: string }> = {
  critical: { bg: "var(--red-bg)",    text: "var(--red)",    label: "Critical" },
  high:     { bg: "var(--orange-bg)", text: "var(--orange)", label: "High"     },
  medium:   { bg: "var(--muted-bg)",  text: "var(--amber)",  label: "Medium"   },
  low:      { bg: "var(--green-bg)",  text: "var(--green)",  label: "Low"      },
};
export function SeverityBadge({ severity }: { severity: string }) {
  const c = CFG[severity] ?? { bg: "var(--muted-bg)", text: "var(--text-3)", label: severity };
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium"
      style={{ background: c.bg, color: c.text, border: `1px solid ${c.bg}` }}>
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: c.text, opacity: 0.8 }} />
      {c.label}
    </span>
  );
}
