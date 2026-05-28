from app.tools.registry import TOOL_REGISTRY

class ToolExecutor:

    async def execute(self, tool_name: str, args: dict):
        tool = TOOL_REGISTRY.get(tool_name)

        if not tool:
            return {"error": "Unknown tool"}

        return await tool(**args)