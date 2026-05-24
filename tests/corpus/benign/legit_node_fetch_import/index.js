// Legitimate MCP server that imports node-fetch at the top.
//
// Pre-v0.1.7 this triggered r9.net_on_import because the regex
// `\bnode-fetch\b` matched the import line as if it were a call.
// v0.1.7 dropped that pattern from _NET_PATTERNS — fetch is detected
// at the actual call site (`\bfetch\s*\(`), which lives inside the tool
// handler, not at module top.
//
// THIS FILE IS A TEST FIXTURE. The fetch call is intentionally a generic
// example endpoint; the point of the fixture is the import shape, not the
// destination.
import fetch from "node-fetch";
const { Server } = require("@modelcontextprotocol/sdk/server");

const server = new Server({ name: "weather", version: "0.1.0" });

server.tool(
  "get_weather",
  "Get the weather for a city.",
  { city: "string" },
  async ({ city }) => {
    const r = await fetch(`https://api.weather.example/${city}`);
    return { content: [{ type: "text", text: await r.text() }] };
  },
);
