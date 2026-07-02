import { useState } from "react";
import { Shield, Terminal } from "lucide-react";
import { api } from "../api/client";

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setLoading(true); setErr("");
    api.setCredentials(user, pass);
    try { await api.getStats(); onLogin(); }
    catch { setErr("ACCESS DENIED — invalid credentials"); api.clearCredentials(); }
    finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg)" }}>
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl mb-4"
            style={{ background: "var(--bg-row)", border: "1px solid #1e3a5f", boxShadow: "0 0 40px rgba(59,130,246,0.1)" }}>
            <Shield className="w-8 h-8" style={{ color: "#ef4444" }} />
          </div>
          <div className="font-bold font-mono tracking-widest" style={{ color: "var(--text)", fontSize: 14, letterSpacing: "0.2em" }}>SANDWALK</div>
          <div className="font-mono text-[10px] tracking-widest mt-1" style={{ color: "var(--text-2)" }}>ENDPOINT SECRETS SCANNER</div>
        </div>
        <form onSubmit={submit} className="rounded-lg p-6 space-y-4" style={{ background: "var(--bg-card)", border: "1px solid #1a2a45" }}>
          <div className="flex items-center gap-2 mb-5">
            <Terminal className="w-3.5 h-3.5" style={{ color: "var(--text-2)" }} />
            <span className="font-mono text-[9px] tracking-widest" style={{ color: "var(--text-3)" }}>AUTHENTICATION REQUIRED</span>
          </div>
          {[{id:"u",label:"USERNAME",type:"text",val:user,set:setUser},{id:"p",label:"PASSWORD",type:"password",val:pass,set:setPass}].map(({id,label,type,val,set}) => (
            <div key={id}>
              <label className="block font-mono text-[9px] tracking-widest mb-1.5" style={{ color: "var(--text-3)" }}>{label}</label>
              <input type={type} value={val} onChange={e => set(e.target.value)} required
                className="w-full px-3 py-2 rounded font-mono text-sm focus:outline-none"
                style={{ background: "var(--bg)", color: "var(--text)", border: "1px solid #1e3a5f" }}
                onFocus={e => (e.target.style.borderColor = "var(--text-2)")}
                onBlur={e => (e.target.style.borderColor = "var(--text-dim)")} />
            </div>
          ))}
          {err && <div className="font-mono text-[11px] py-2 px-3 rounded" style={{ background: "var(--red-bg)", color: "var(--red)", border: "1px solid #5a1a1a" }}>{err}</div>}
          <button type="submit" disabled={loading} className="w-full py-2.5 rounded font-mono text-sm tracking-widest transition-all disabled:opacity-50"
            style={{ background: "var(--bg-row)", color: "var(--text-2)", border: "1px solid #1e3a5f" }}>
            {loading ? "AUTHENTICATING..." : "AUTHENTICATE"}
          </button>
        </form>
        <div className="text-center mt-4 font-mono text-[9px] tracking-widest" style={{ color: "var(--text-dim)" }}>
          SANDWALK
        </div>
      </div>
    </div>
  );
}
