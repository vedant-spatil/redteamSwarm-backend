import asyncio
import uuid
import json

from app.agents.memory import AgentMemory
from app.agents.tool_executor import ToolExecutor
from app.agents.finding_extractor import FindingExtractor

from app.llm.ollama_client import OllamaClient

from app.agents.prompts import SYSTEM_PROMPT

from app.tools.registry import TOOL_SCHEMAS


class AutonomousAgent:

    def __init__(self, target_url: str, focus_area: str):

        self.agent_id = str(uuid.uuid4())[:8]

        self.target_url = target_url
        self.focus_area = focus_area

        self.memory = AgentMemory()

        self.tool_executor = ToolExecutor()
        self.finding_extractor = FindingExtractor()

        self.llm = OllamaClient()

        self.running = True

    async def bootstrap(self):

        self.memory.add(
            "system",
            SYSTEM_PROMPT
        )

        self.memory.add(
            "user",
            f"""
Target URL:
{self.target_url}

Focus Area:
{self.focus_area}

Begin testing immediately.

Allowed parameters:
- id
- q
- search
- file
- redirect

You MUST use tools.
"""
        )

    def extract_tool_calls_from_content(
        self,
        content: str
    ):

        tool_calls = []

        try:

            cleaned = (
                content
                .replace("```json", "")
                .replace("```", "")
                .strip()
            )

            decoder = json.JSONDecoder()

            idx = 0

            while idx < len(cleaned):

                try:

                    obj, end = decoder.raw_decode(
                        cleaned[idx:]
                    )

                    if (
                        isinstance(obj, dict)
                        and "name" in obj
                        and "arguments" in obj
                    ):

                        tool_calls.append({
                            "function": {
                                "name": obj["name"],
                                "arguments": obj["arguments"],
                            }
                        })

                    idx += end

                except json.JSONDecodeError:
                    idx += 1

        except Exception as e:

            print(
                f"[{self.agent_id}] PARSER ERROR:"
            )

            print(str(e))

        return tool_calls

    async def run(self):

        await self.bootstrap()

        while self.running:

            try:

                response = await self.llm.chat(
                    self.memory.messages,
                    tools=TOOL_SCHEMAS,
                )

                message = response.get(
                    "message",
                    {}
                )

                content = message.get(
                    "content",
                    ""
                )

                if content:

                    print(
                        f"[{self.agent_id}] THINKING:"
                    )

                    print(content)

                    self.memory.add(
                        "assistant",
                        content,
                    )

                tool_calls = message.get(
                    "tool_calls",
                    []
                )

                # Fallback parser
                if not tool_calls and content:

                    tool_calls = (
                        self.extract_tool_calls_from_content(
                            content
                        )
                    )

                print(
                    f"[{self.agent_id}] TOOL CALLS:"
                )

                print(tool_calls)

                if not tool_calls:

                    print(
                        f"[{self.agent_id}] No tool calls generated"
                    )

                for tool_call in tool_calls:

                    function_data = tool_call.get(
                        "function",
                        {}
                    )

                    tool_name = function_data.get(
                        "name"
                    )

                    arguments = function_data.get(
                        "arguments",
                        {}
                    )

                    # Fix hallucinated schema values

                    url_value = arguments.get("url")

                    if (
                        not isinstance(url_value, str)
                        or "http" not in url_value
                    ):
                        arguments["url"] = self.target_url

                    parameter_value = arguments.get("parameter")

                    if (
                        not isinstance(parameter_value, str)
                    ):
                        arguments["parameter"] = "q"

                    print(
                        f"[{self.agent_id}] USING TOOL:"
                    )

                    print(tool_name)

                    print(arguments)

                    result = await self.tool_executor.execute(
                        tool_name,
                        arguments,
                    )

                    print(
                        f"[{self.agent_id}] TOOL RESULT:"
                    )

                    print(result)

                    self.memory.add(
                        "tool",
                        str(result)
                    )

                    finding = (
                        self.finding_extractor.extract(
                            tool_name,
                            result,
                        )
                    )

                    if finding:

                        print(
                            f"[{self.agent_id}] FOUND VULNERABILITY:"
                        )

                        print(finding)

                        self.memory.add(
                            "assistant",
                            f"""
Vulnerability discovered:

{finding}
"""
                        )

                        from app.orchestrator.swarm_manager import ( swarm_manager ) 
                        swarm_manager.findings.append( finding )

                await asyncio.sleep(2)

            except Exception as e:

                print(
                    f"[{self.agent_id}] ERROR:"
                )

                print(str(e))

                await asyncio.sleep(3)