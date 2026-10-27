// A scripted "model" behind an OpenAI-compatible chat completions API, so a
// real agent runtime (OpenClaw, Hermes) can be driven through tool calls
// without an API key (IG5). It is not a model: on each request it counts the
// tool results already in the conversation and asks for the next scripted
// call; when the script ends it answers with the tool results it saw. Logs
// every request's tool names and tool results to stderr.
//
//   SCRIPT=script.json [HOST=0.0.0.0] node scripted-model.js   (port 8099)
const http = require("http");
const fs = require("fs");
const script = JSON.parse(fs.readFileSync(process.env.SCRIPT || "script.json", "utf8"));

function reply(body) {
  const messages = body.messages || [];
  const offered = (body.tools || []).map((t) => t.function && t.function.name).filter(Boolean);
  if (process.env.DUMP_TOOLS) fs.writeFileSync(process.env.DUMP_TOOLS, JSON.stringify(body.tools || [], null, 2));
  // Which tool each earlier call used, to tell search results from scripted ones.
  const calledName = {};
  for (const m of messages) for (const c of m.tool_calls || []) calledName[c.id] = c.function && c.function.name;
  const results = messages.filter((m) => m.role === "tool");
  const text = (r) => (typeof r.content === "string" ? r.content : JSON.stringify(r.content));
  const searches = results.filter((r) => calledName[r.tool_call_id] === "tool_search");
  const scripted = results.filter((r) => calledName[r.tool_call_id] !== "tool_search");
  console.error(`[model] ${messages.length} messages, ${scripted.length} scripted results; tools: ${offered.join(", ")}`);
  for (const r of results) console.error(`[model] result (${calledName[r.tool_call_id]}): ${text(r).slice(0, 400)}`);
  const n = results.length + 1;
  if (results.length > 20) return { text: "Script aborted: more than 20 calls." };
  const step = script[scripted.length];
  if (step) {
    const direct = offered.find((o) => o === step.tool || o.endsWith("__" + step.tool) || o.endsWith("_" + step.tool) || o.endsWith("." + step.tool));
    if (direct) return { tool: { id: `call_${n}`, name: direct, arguments: JSON.stringify(step.args) } };
    // OpenClaw keeps MCP tools behind tool_search / tool_call.
    if (offered.includes("tool_call")) {
      // Hermes lists the deferred tools in tool_search's description; OpenClaw
      // only in search results. Their tool_call arguments differ too.
      const catalog = searches.map(text).join("\n") + JSON.stringify(body.tools || []);
      const found = catalog.match(new RegExp(`[\\w.:/-]*__${step.tool}\\b`));
      const schema = (body.tools.find((t) => t.function.name === "tool_call").function.parameters || {}).properties || {};
      // Newer Hermes takes a list of queries; older Hermes and OpenClaw one.
      const search = ((body.tools.find((t) => t.function.name === "tool_search") || {}).function || {}).parameters || {};
      const query = step.tool.replace("_", " ");
      const searchArgs = (search.properties || {}).queries ? { queries: [query] } : { query };
      if (!found) return { tool: { id: `call_${n}`, name: "tool_search", arguments: JSON.stringify(searchArgs) } };
      const args = schema.calls ? { calls: [{ name: found[0], arguments: step.args }] } : { id: found[0], args: step.args };
      return { tool: { id: `call_${n}`, name: "tool_call", arguments: JSON.stringify(args) } };
    }
    return { text: `tool ${step.tool} not offered; offered: ${offered.join(", ")}` };
  }
  const seen = scripted.map((r, i) => `${i + 1}. ${script[i] ? script[i].tool : "?"}: ${text(r)}`);
  return { text: "Script done. Results:\n" + seen.join("\n") };
}

function completion(out, model) {
  const message = out.tool
    ? { role: "assistant", content: null, tool_calls: [{ id: out.tool.id, type: "function", function: { name: out.tool.name, arguments: out.tool.arguments } }] }
    : { role: "assistant", content: out.text };
  return {
    id: "scripted-" + Date.now(), object: "chat.completion", created: Math.floor(Date.now() / 1000), model,
    choices: [{ index: 0, message, finish_reason: out.tool ? "tool_calls" : "stop" }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  };
}

function stream(res, out, model) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  const base = { id: "scripted-" + Date.now(), object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model };
  const send = (choice, extra = {}) => res.write(`data: ${JSON.stringify({ ...base, choices: [choice], ...extra })}\n\n`);
  if (out.tool) {
    send({ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, id: out.tool.id, type: "function", function: { name: out.tool.name, arguments: out.tool.arguments } }] }, finish_reason: null });
    send({ index: 0, delta: {}, finish_reason: "tool_calls" });
  } else {
    send({ index: 0, delta: { role: "assistant", content: out.text }, finish_reason: null });
    send({ index: 0, delta: {}, finish_reason: "stop" });
  }
  res.write(`data: ${JSON.stringify({ ...base, choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}\n\n`);
  res.end("data: [DONE]\n\n");
}

http.createServer((req, res) => {
  let data = "";
  req.on("data", (c) => (data += c));
  req.on("end", () => {
    if (req.method === "GET" && req.url.endsWith("/models")) {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ object: "list", data: [{ id: "scripted", object: "model", owned_by: "cleimesh-tests" }] }));
    }
    if (!req.url.endsWith("/chat/completions")) {
      console.error(`[model] ${req.method} ${req.url}: not supported`);
      res.writeHead(404);
      return res.end();
    }
    const body = JSON.parse(data || "{}");
    const out = reply(body);
    if (body.stream) return stream(res, out, body.model || "scripted");
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(completion(out, body.model || "scripted")));
  });
}).listen(8099, process.env.HOST || "127.0.0.1", () => console.error(`[model] listening on ${process.env.HOST || "127.0.0.1"}:8099`));
