"""
Autonomous Agent Loop.

Implements the core insight from the Anthropic AAR paper:
  "Autonomous scaffolding outperforms prescriptive scaffolding."

The agent runs a simple `while True` loop — no fixed state machine.
It reads the shared forum, decides what to do next, calls tools,
and writes discoveries back to the forum. The LLM itself drives the
research strategy.

Each agent is seeded with a distinct focus area (like the paper's
"diverse research directions") to prevent entropy collapse.
"""
import json
import time
import threading
from datetime import datetime
from typing import Optional
import httpx

from models import AgentStatus, Finding, ForumEntry, LogEntry
from forum import forum
from tools import TOOL_REGISTRY, TOOL_SCHEMAS

FOCUS_AREAS = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal & Exposed Files",
    "Authentication & Authorization Bypass",
    "Security Header Misconfiguration",
    "Open Ports & Service Exposure",
    "API Endpoint Discovery",
    "CSRF & State-Changing Requests",
]


class Agent:
    """
    A single autonomous red-team agent.

    Mirrors the paper's AAR design:
    - Reads forum context before each iteration
    - Proposes its own next action (no rigid plan)
    - Shares discoveries back to forum immediately
    - Runs indefinitely until stopped
    """

    def __init__(
        self,
        agent_id: str,
        target_url: str,
        focus_area: str,
        ollama_model: str = "qwen2.5-coder:3b",
        ollama_host: str = "http://localhost:11434",
        max_iterations: int = 50,
    ):
        self.agent_id = agent_id
        self.target_url = target_url
        self.focus_area = focus_area
        self.ollama_model = ollama_model
        self.ollama_host = ollama_host.rstrip("/")
        self.max_iterations = max_iterations

        self._stop_event = threading.Event()
        self._status = AgentStatus(
            agent_id=agent_id,
            focus_area=focus_area,
            status="idle",
        )

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    def stop(self):
        self._stop_event.set()

    def get_status(self) -> AgentStatus:
        return self._status

    def run(self):
        """Main agent loop — runs in its own thread."""
        self._log("INFO", f"Agent started | focus: {self.focus_area} | target: {self.target_url}")
        self._update_status("running", "Initialising…")

        messages = self._build_initial_messages()
        iteration = 0

        while not self._stop_event.is_set() and iteration < self.max_iterations:
            iteration += 1
            self._status.iteration = iteration

            try:
                self._update_status("running", f"Iteration {iteration}: thinking…")
                response = self._ollama_chat(messages)

                if response is None:
                    self._log("WARN", "No response from Ollama, sleeping…")
                    time.sleep(5)
                    continue

                # ── Handle tool calls ──────────────────────────────── #
                tool_calls = response.get("message", {}).get("tool_calls", [])
                if tool_calls:
                    messages.append(response["message"])
                    for call in tool_calls:
                        result = self._execute_tool(call)
                        messages.append({
                            "role": "tool",
                            "content": json.dumps(result),
                        })
                    # Inject refreshed forum context every 5 iterations
                    if iteration % 5 == 0:
                        messages = self._inject_forum_update(messages)
                    continue

                # ── Handle text response (finding / observation) ───── #
                content = response.get("message", {}).get("content", "")
                if content:
                    self._process_text_response(content)
                    messages.append({"role": "assistant", "content": content})
                    # Add a nudge to keep probing
                    messages.append({
                        "role": "user",
                        "content": (
                            f"Continue probing. Forum update:\n"
                            f"{forum.get_summary_for_agent(self.agent_id)}\n\n"
                            "Use a tool to test your next hypothesis."
                        ),
                    })

            except Exception as e:
                self._log("ERROR", f"Agent error: {e}")
                time.sleep(3)

        self._update_status("done", "Completed")
        self._log("INFO", f"Agent finished after {iteration} iterations")

    # ------------------------------------------------------------------ #
    #  Ollama API                                                          #
    # ------------------------------------------------------------------ #

    def _ollama_chat(self, messages: list) -> Optional[dict]:
        try:
            with httpx.Client(timeout=120.0) as c:
                resp = c.post(
                    f"{self.ollama_host}/api/chat",
                    json={
                        "model": self.ollama_model,
                        "messages": messages,
                        "tools": TOOL_SCHEMAS,
                        "stream": False,
                        "options": {"temperature": 0.3},
                    },
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.ConnectError:
            self._log("ERROR", f"Cannot reach Ollama at {self.ollama_host}. Is it running?")
            time.sleep(10)
            return None
        except Exception as e:
            self._log("ERROR", f"Ollama call failed: {e}")
            return None

    # ------------------------------------------------------------------ #
    #  Tool execution                                                      #
    # ------------------------------------------------------------------ #

    def _execute_tool(self, call: dict) -> dict:
        fn_name = call.get("function", {}).get("name", "")
        raw_args = call.get("function", {}).get("arguments", {})

        # Ollama may pass arguments as a JSON string
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except Exception:
                args = {}
        else:
            args = raw_args

        self._log("TOOL", f"→ {fn_name}({json.dumps(args)[:120]})")
        self._update_status("running", f"Running tool: {fn_name}")

        if fn_name not in TOOL_REGISTRY:
            return {"error": f"Unknown tool: {fn_name}"}

        try:
            result = TOOL_REGISTRY[fn_name](**args)
            self._auto_extract_finding(fn_name, args, result)
            return result
        except Exception as e:
            err = str(e)
            self._log("ERROR", f"Tool {fn_name} failed: {err}")
            return {"error": err}

    def _auto_extract_finding(self, tool_name: str, args: dict, result: dict):
        """
        Automatically promote tool results to confirmed findings so
        the forum is updated even if the LLM doesn't write a finding.
        """
        url = args.get("url") or args.get("base_url") or args.get("login_url") or self.target_url

        if tool_name == "check_sql_injection" and result.get("vulnerable"):
            for f in result["findings"]:
                self._submit_finding(
                    severity="HIGH",
                    vuln_type="SQL Injection",
                    description=f"SQLi ({f['style']}) via param '{args.get('parameter')}'",
                    evidence=f.get("evidence", ""),
                    url=url,
                    parameter=args.get("parameter"),
                    payload=f.get("payload"),
                    confidence=f.get("confidence", "MEDIUM"),
                )

        elif tool_name == "check_xss" and result.get("vulnerable"):
            for f in result["findings"]:
                self._submit_finding(
                    severity="MEDIUM",
                    vuln_type="Cross-Site Scripting (XSS)",
                    description=f"Reflected XSS via param '{args.get('parameter')}'",
                    evidence=f.get("evidence", ""),
                    url=url,
                    parameter=args.get("parameter"),
                    payload=f.get("payload"),
                    confidence=f.get("confidence", "MEDIUM"),
                )

        elif tool_name == "scan_directories":
            for d in result.get("discovered", []):
                sev = d.get("severity", "LOW")
                if sev in ("CRITICAL", "HIGH"):
                    self._submit_finding(
                        severity=sev,
                        vuln_type="Exposed Sensitive Path",
                        description=f"Path {d['path']} accessible (HTTP {d['status']})",
                        evidence=d.get("snippet", "")[:200],
                        url=url + d["path"],
                        confidence="HIGH",
                    )

        elif tool_name == "check_auth_bypass" and result.get("vulnerable"):
            for f in result["findings"]:
                self._submit_finding(
                    severity="CRITICAL",
                    vuln_type="Authentication Bypass",
                    description=f"{f['type']} with '{f.get('username','')}'",
                    evidence=f.get("evidence", ""),
                    url=url,
                    confidence=f.get("confidence", "MEDIUM"),
                )

        elif tool_name == "check_security_headers":
            for issue in result.get("issues", []):
                if issue["severity"] in ("HIGH", "CRITICAL"):
                    self._submit_finding(
                        severity=issue["severity"],
                        vuln_type="Security Misconfiguration",
                        description=f"{issue['description']}",
                        evidence=f"Header '{issue['header']}' missing",
                        url=url,
                        confidence="HIGH",
                    )

        elif tool_name == "port_scan":
            for p in result.get("open_ports", []):
                if p["severity"] in ("HIGH", "CRITICAL"):
                    self._submit_finding(
                        severity=p["severity"],
                        vuln_type="Exposed Service",
                        description=f"Port {p['port']} ({p['service']}) exposed",
                        evidence=f"Port {p['port']} responded to TCP connect",
                        url=args.get("host", url),
                        confidence="HIGH",
                    )

    def _submit_finding(
        self,
        severity: str,
        vuln_type: str,
        description: str,
        evidence: str,
        url: str,
        parameter: Optional[str] = None,
        payload: Optional[str] = None,
        confidence: str = "MEDIUM",
    ):
        if forum.has_finding_for(url, parameter, vuln_type):
            return  # Skip duplicates — mirrors anti-reward-hacking logic

        finding = Finding(
            severity=severity,
            vuln_type=vuln_type,
            description=description,
            evidence=evidence,
            url=url,
            parameter=parameter,
            payload=payload,
            agent_id=self.agent_id,
            confirmed=confidence == "HIGH",
        )
        forum.add_finding(finding)
        self._status.finding_count += 1
        self._log("FINDING", f"[{severity}] {vuln_type}: {description}")

    # ------------------------------------------------------------------ #
    #  Text response processing                                            #
    # ------------------------------------------------------------------ #

    def _process_text_response(self, content: str):
        """Parse LLM narrative and post to forum."""
        self._log("INFO", content[:200])
        forum.post(ForumEntry(
            agent_id=self.agent_id,
            focus_area=self.focus_area,
            message=content[:300],
        ))

    # ------------------------------------------------------------------ #
    #  Message construction                                                #
    # ------------------------------------------------------------------ #

    def _build_initial_messages(self) -> list:
        return [
            {
                "role": "system",
                "content": (
                    f"You are an autonomous red-team security agent (ID: {self.agent_id}).\n"
                    f"Target: {self.target_url}\n"
                    f"Your assigned focus area: {self.focus_area}\n\n"
                    "MISSION: Find real, exploitable vulnerabilities. Be systematic.\n"
                    "RULES:\n"
                    "  1. Use tools to test hypotheses — don't just describe attacks.\n"
                    "  2. Start broad (port scan, headers, directory scan) then go deep.\n"
                    "  3. Avoid repeating attacks other agents have already confirmed.\n"
                    "  4. Each tool call should test a new hypothesis.\n"
                    "  5. When you find something interesting, call another tool to confirm it.\n\n"
                    "Shared Forum (other agents' findings):\n"
                    f"{forum.get_summary_for_agent(self.agent_id)}\n\n"
                    "Begin probing now. Use a tool for your first action."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Start your security assessment of {self.target_url}. "
                    f"Focus on: {self.focus_area}. "
                    "Use your tools to actively test — not just theorize."
                ),
            },
        ]

    def _inject_forum_update(self, messages: list) -> list:
        """Append a forum-update message to keep agents informed."""
        summary = forum.get_summary_for_agent(self.agent_id)
        messages.append({
            "role": "user",
            "content": f"Forum update from other agents:\n{summary}\n\nContinue your investigation.",
        })
        return messages

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _update_status(self, status: str, task: str):
        self._status.status = status
        self._status.current_task = task
        self._status.last_seen = datetime.utcnow().isoformat()

    def _log(self, level: str, message: str):
        forum.log(LogEntry(agent_id=self.agent_id, level=level, message=message))