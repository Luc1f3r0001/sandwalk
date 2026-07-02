import { formatDistanceToNow } from "date-fns";

// Server timestamps have no timezone marker — treat as UTC
export function parseUTC(ts: string): Date {
  if (!ts) return new Date();
  if (ts.includes("Z") || ts.includes("+")) return new Date(ts);
  return new Date(ts + "Z");
}

export function timeAgo(ts: string): string {
  return formatDistanceToNow(parseUTC(ts), { addSuffix: true });
}

export function toIST(ts: string): string {
  return parseUTC(ts).toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  });
}
