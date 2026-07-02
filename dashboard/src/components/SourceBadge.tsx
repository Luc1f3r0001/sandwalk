import { Laptop, GitBranch } from "lucide-react";
export function SourceBadge({ source }: { source: string }) {
  if (source === "git") return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium"
      style={{ background: "var(--purple-bg)", color: "var(--purple)" }}>
      <GitBranch className="w-3 h-3" />Git
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium"
      style={{ background: "var(--accent-bg)", color: "var(--text-2)" }}>
      <Laptop className="w-3 h-3" />Machine
    </span>
  );
}
