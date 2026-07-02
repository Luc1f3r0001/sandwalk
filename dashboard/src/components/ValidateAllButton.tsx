import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, X, Loader2 } from "lucide-react";
import { api } from "../api/client";
import type { ValidateAllResult } from "../types";
export function ValidateAllButton({ machineId }: { machineId: string }) {
  const [result, setResult] = useState<ValidateAllResult | null>(null);
  const qc = useQueryClient();
  const mut = useMutation({
    mutationFn: () => api.validateAll(machineId),
    onSuccess: r => { setResult(r); qc.invalidateQueries({ queryKey: ["machine", machineId] }); qc.invalidateQueries({ queryKey: ["findings"] }); }
  });
  return (
    <>
      <button onClick={() => mut.mutate()} disabled={mut.isPending}
        className="inline-flex items-center gap-1.5 rounded-md font-medium transition-colors disabled:opacity-40"
        style={{ padding: "5px 12px", fontSize: 12, background: "var(--green-bg)", color: "var(--green)", border: "1px solid var(--green-bd)", cursor: "pointer" }}>
        {mut.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
        {mut.isPending ? "Dispatching…" : "Re-validate"}
      </button>
      {result && (
        <div className="fixed inset-0 flex items-center justify-center z-50" style={{ background: "rgba(0,0,0,0.7)" }} onClick={() => setResult(null)}>
          <div className="rounded-xl max-w-md w-full mx-4 shadow-2xl" style={{ background: "var(--bg-card)", border: "1px solid var(--border-hi)" }} onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
              <div className="flex items-center gap-2 text-sm font-semibold" style={{ color: "var(--text)" }}>
                <ShieldCheck className="w-4 h-4" style={{ color: "var(--green)" }} /> Re-validation dispatched
              </div>
              <button onClick={() => setResult(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)" }}><X className="w-4 h-4" /></button>
            </div>
            <div className="p-5">
              <p style={{ fontSize: 13, color: "var(--text-2)", lineHeight: 1.6 }}>{result.message}</p>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
