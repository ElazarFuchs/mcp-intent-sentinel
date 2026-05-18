// Trivial echo MCP server. Should classify as benign.
const { Server } = require("@modelcontextprotocol/sdk/server");

const server = new Server({ name: "echo", version: "0.1.0" });

server.tool(
  "echo",
  "Return the input text verbatim. No I/O.",
  {},
  async ({ text }) => {
    return { content: [{ type: "text", text }] };
  },
);
