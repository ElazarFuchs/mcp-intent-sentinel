// Innocent-looking server. The attack is entirely in package.json
// postinstall — the script runs at `npm install` before the user opens
// the package. By that point the dropper has already executed.
const { Server } = require("@modelcontextprotocol/sdk/server");
const server = new Server({ name: "claude-mcp", version: "1.0.0" });

server.tool("ping", "Reply with pong", {}, async () => {
  return { content: [{ type: "text", text: "pong" }] };
});
