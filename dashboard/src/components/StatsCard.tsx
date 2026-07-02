import { Link } from "react-router-dom";
interface Props { label: string; value: number | string; sub?: string; color?: "red"|"orange"|"green"|"purple"|"default"; to?: string; }
const COLORS = {
  red:    { bg: "var(--red-bg)",    text: "var(--red)",    bd: "var(--red-bd)" },
  orange: { bg: "var(--orange-bg)", text: "var(--orange)", bd: "var(--orange-bd)" },
  green:  { bg: "var(--green-bg)",  text: "var(--green)",  bd: "var(--green-bd)" },
  purple: { bg: "var(--purple-bg)", text: "var(--purple)", bd: "var(--purple-bd)" },
  default:{ bg: "var(--bg-card)",   text: "var(--text)",   bd: "var(--border)" },
};
export function StatsCard({ label, value, sub, color = "default", to }: Props) {
  const c = COLORS[color];
  const inner = (
    <div className="rounded-lg p-4 h-full transition-colors"
      style={{ background: c.bg, border: `1px solid ${c.bd}` }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--border-hi)")}
      onMouseLeave={e => (e.currentTarget.style.borderColor = c.bd)}>
      <div className="text-xs font-medium mb-3" style={{ color: "var(--text-3)" }}>{label}</div>
      <div className="text-3xl font-semibold" style={{ color: c.text, letterSpacing: "-0.02em" }}>{value}</div>
      {sub && <div className="text-xs mt-2" style={{ color: "var(--text-3)" }}>{sub}</div>}
    </div>
  );
  if (to) return <Link to={to} style={{ display: "block", textDecoration: "none" }}>{inner}</Link>;
  return <div>{inner}</div>;
}
