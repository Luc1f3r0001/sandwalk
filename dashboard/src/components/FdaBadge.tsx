import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
export function FdaBadge({ granted, compact }: { granted?: boolean | null; compact?: boolean }) {
  if (granted === true) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium"
      style={{ background: "var(--green-bg)", color: "var(--green)" }}>
      <ShieldCheck className="w-3 h-3" />{compact ? "FDA" : "Granted"}
    </span>
  );
  if (granted === false) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium"
      style={{ background: "var(--red-bg)", color: "var(--red)" }}>
      <ShieldAlert className="w-3 h-3" />{compact ? "No FDA" : "Denied"}
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs"
      style={{ background: "var(--muted-bg)", color: "var(--text-3)" }}>
      <ShieldQuestion className="w-3 h-3" />{compact ? "—" : "Unknown"}
    </span>
  );
}
