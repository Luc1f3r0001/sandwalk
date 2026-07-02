import type { Machine, Finding, Stats, FindingStatus } from "../types";

const BASE = "/api";

function authHeader(): string {
  const user = sessionStorage.getItem("admin_user") || "";
  const pass = sessionStorage.getItem("admin_pass") || "";
  return "Basic " + btoa(`${user}:${pass}`);
}

async function get<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(BASE + path, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => v && url.searchParams.set(k, v));
  }
  const res = await fetch(url.toString(), {
    headers: { Authorization: authHeader() },
  });
  if (res.status === 401) throw new Error("UNAUTHORIZED");
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: authHeader(),
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401) throw new Error("UNAUTHORIZED");
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: authHeader(),
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401) throw new Error("UNAUTHORIZED");
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

import type { ValidateAllResult } from "../types";

export const api = {
  getMachines: () => get<Machine[]>("/machines"),

  validateAll: (machineId: string) =>
    post<ValidateAllResult>(`/machines/${machineId}/validate-all`, {}),

  getMachine: (id: string) =>
    get<{ machine: Machine; recent_scans: unknown[] }>(`/machines/${id}`),

  getFindings: (params?: {
    machine_id?: string;
    severity?: string;
    status?: string;
    category?: string;
    source_type?: string;
    limit?: number;
    offset?: number;
  }) =>
    get<Finding[]>("/findings", {
      ...(params?.machine_id ? { machine_id: params.machine_id } : {}),
      ...(params?.severity ? { severity: params.severity } : {}),
      ...(params?.status ? { status: params.status } : {}),
      ...(params?.category ? { category: params.category } : {}),
      ...(params?.source_type ? { source_type: params.source_type } : {}),
      ...(params?.limit ? { limit: String(params.limit) } : {}),
      ...(params?.offset ? { offset: String(params.offset) } : {}),
    }),

  getStats: () => get<Stats>("/findings/stats"),

  updateFinding: (id: string, status: FindingStatus, notes?: string) =>
    patch(`/findings/${id}`, { status, notes }),

  reverifyFinding: (id: string) =>
    post<{ dispatched: boolean; message: string }>(`/findings/${id}/verify`, {}),

  requestRescan: (machineId: string, scope = "standard") =>
    post(`/machines/${machineId}/rescan`, { scope }),

  getRescanStatus: (machineId: string) =>
    get<{ status: string; requested_at?: string; fulfilled_at?: string; scope?: string }>(
      `/machines/${machineId}/rescan-status`
    ),

  exportCsvUrl: (status = "open") => `/api/export/csv?status=${status}`,
  exportSarifUrl: () => `/api/export/sarif`,

  setCredentials: (user: string, pass: string) => {
    sessionStorage.setItem("admin_user", user);
    sessionStorage.setItem("admin_pass", pass);
  },

  clearCredentials: () => {
    sessionStorage.removeItem("admin_user");
    sessionStorage.removeItem("admin_pass");
  },

  hasCredentials: () => !!sessionStorage.getItem("admin_user"),
};
