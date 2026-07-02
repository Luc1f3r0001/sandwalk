export type FindingStatus = "open" | "fixed" | "rotated" | "removed_active";
const CFG: Record<string, { bg: string; text: string; label: string }> = {
  open:          { bg: "var(--red-bg)",    text: "var(--red)",    label: "Open"         },
  fixed:         { bg: "var(--green-bg)",  text: "var(--green)",  label: "Fixed"        },
  rotated:       { bg: "var(--green-bg)",  text: "var(--green)",  label: "Rotated"      },
  removed_active:{ bg: "var(--purple-bg)", text: "var(--purple)", label: "Removed · Live"},
};
export function StatusBadge({ status }: { status: string }) {
  const c = CFG[status] ?? { bg: "var(--muted-bg)", text: "var(--text-3)", label: status };
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium"
      style={{ background: c.bg, color: c.text }}>{c.label}
    </span>
  );
}
