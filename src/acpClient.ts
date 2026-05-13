// acpClient — calls platform tools on the ACP gateway via MCP.
//
// Every governed tool handler delegates to acpCall() by default — this
// runs the platform-managed implementation under ACP policy + audit.
//
// To self-host a tool: replace the tool's handler body in index.ts with
// your own implementation. acpCall stays available for the other tools.

export async function acpCall(toolName: string, args: Record<string, unknown>): Promise<string> {
  const base = (process.env.ACP_GATEWAY_URL ?? "").replace(/\/+$/, "");
  const tenant = process.env.ACP_TENANT_SLUG ?? "";
  const token = process.env.ACP_TOKEN ?? process.env.FIREBASE_ID_TOKEN ?? "";
  if (!base) throw new Error("ACP_GATEWAY_URL env var not set");
  if (!tenant) throw new Error("ACP_TENANT_SLUG env var not set");
  if (!token) throw new Error("ACP_TOKEN env var not set");

  const resp = await fetch(`${base}/${tenant}/mcp`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: toolName, arguments: args },
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`ACP tool '${toolName}' HTTP ${resp.status}: ${text}`);
  }
  const data = await resp.json() as Record<string, unknown>;
  if (data.error) {
    const e = data.error as Record<string, unknown>;
    throw new Error(`ACP tool '${toolName}' failed: ${e?.message ?? JSON.stringify(e)}`);
  }
  const result = (data.result ?? {}) as Record<string, unknown>;
  if (Array.isArray(result.content)) {
    const parts = (result.content as Array<Record<string, unknown>>)
      .filter((b) => b.type === "text")
      .map((b) => String(b.text ?? ""));
    if (parts.length) return parts.join("\n");
  }
  return typeof result === "string" ? result : JSON.stringify(result);
}
