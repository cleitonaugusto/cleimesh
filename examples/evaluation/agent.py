"""A scripted agent (no model): calls tools through the cleimesh wrapper and prints one line per call.
Usage: agent.py '<json list of [tool, arguments]>'"""
import asyncio, json, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main(calls):
    wrap = StdioServerParameters(command="cleimesh", args=["mcp", "wrap"], env=dict(os.environ))
    async with stdio_client(wrap) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = [t.name for t in (await s.list_tools()).tools]
            print("TOOLS " + ",".join(sorted(tools)), flush=True)
            for name, args in calls:
                res = await s.call_tool(name, args)
                text = (res.content[0].text if res.content else "").replace("\n", " ")
                err = getattr(res, "is_error", None)
                err = getattr(res, "isError", False) if err is None else err
                print(("REFUSED " if err else "OK ") + name + " | " + text[:300], flush=True)

asyncio.run(main(json.loads(sys.argv[1])))
