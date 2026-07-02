import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, WifiOff } from "lucide-react";
import { api } from "../api/client";
import { formatDistanceToNow } from "date-fns";

export function RescanButton({ machineId, size = "default" }: { machineId: string; size?: "sm"|"default" }) {
  const qc = useQueryClient();
  const { data: status } = useQuery({
    queryKey: ["rescan", machineId],
    queryFn: () => api.getRescanStatus(machineId),
    refetchInterval: 10_000,
  });
  const mut = useMutation({
    mutationFn: () => api.requestRescan(machineId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rescan", machineId] }),
  });

  const pending = status?.status === "pending";
  const sm = size === "sm";

  // If the request has been pending for >5 min, the machine is likely offline.
  const stale = pending && status?.requested_at
    ? (Date.now() - new Date(status.requested_at).getTime()) > 5 * 60 * 1000
    : false;

  const label = stale
    ? `Pending ${formatDistanceToNow(new Date(status!.requested_at!), { addSuffix: false })}`
    : pending
    ? "Scanning…"
    : "Rescan";

  const title = stale
    ? `Rescan requested ${formatDistanceToNow(new Date(status!.requested_at!), { addSuffix: true })} — machine appears offline. Will run when it comes back online.`
    : pending
    ? "Scan in progress…"
    : "Request a rescan of this machine";

  return (
    <button
      onClick={e => { e.stopPropagation(); mut.mutate(); }}
      disabled={pending || mut.isPending}
      className="inline-flex items-center gap-1.5 rounded-md font-medium transition-colors disabled:opacity-50"
      style={{
        padding: sm ? "3px 10px" : "5px 12px",
        fontSize: sm ? 11 : 12,
        background: stale ? "var(--orange-bg)" : "var(--bg-row)",
        color: stale ? "var(--orange)" : pending ? "var(--text-3)" : "var(--text-2)",
        border: `1px solid ${stale ? "var(--orange-bd)" : "var(--border)"}`,
        cursor: pending ? "default" : "pointer",
        maxWidth: sm ? 140 : "none",
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}
      title={title}
      onMouseEnter={e => !pending && (e.currentTarget.style.color = "var(--text)")}
      onMouseLeave={e => (e.currentTarget.style.color = stale ? "var(--orange)" : pending ? "var(--text-3)" : "var(--text-2)")}>
      {stale
        ? <WifiOff className={sm ? "w-3 h-3" : "w-3.5 h-3.5"} />
        : <RefreshCw className={`${sm ? "w-3 h-3" : "w-3.5 h-3.5"} ${pending && !stale ? "animate-spin" : ""}`} />}
      {label}
    </button>
  );
}
