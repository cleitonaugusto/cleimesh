"""A scripted agent (no LLM) that does what an injected model would do."""
import asyncio, json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

def server(path):
    entry = json.loads(open(path).read().splitlines()[1])
    (name, s), = entry["mcpServers"].items()
    return name, StdioServerParameters(command=s["command"], args=s["args"])

def show(label, res):
    text = " ".join(c.text for c in res.content if hasattr(c, "text"))[:160].replace("\n", " ")
    print(f"  {label:<44} -> {'REFUSED' if res.isError else 'ok'} | {text}")

async def main():
    # `mcp add` registers one client entry for every server it added.
    name, params = server("/tmp/fs.out")
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            print(f"  client entry {name}: {len(tools)} tools from fetch + filesystem")
            show("1. write_file notes.txt (clean)", await s.call_tool("write_file", {"path": "/data/public/notes.txt", "content": "draft"}))
            show("2. fetch the release-notes page", await s.call_tool("fetch", {"url": "http://127.0.0.1:8000/"}))
            show("3. read_text_file secrets.txt", await s.call_tool("read_text_file", {"path": "/data/secrets.txt"}))
            show("4. write_file leak.txt (injected)", await s.call_tool("write_file", {"path": "/data/public/leak.txt", "content": "AWS_SECRET_ACCESS_KEY=demo-not-a-real-key"}))

asyncio.run(main())
