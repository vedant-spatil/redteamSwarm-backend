from app.tools.sql_tools import check_sql_injection
from app.tools.xss_tools import check_xss
from app.tools.port_tools import port_scan


TOOL_REGISTRY = {
    "check_sql_injection": check_sql_injection,
    "check_xss": check_xss,
    "port_scan": port_scan,
}


TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "check_sql_injection",
            "description": "Check endpoint for SQL injection vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "parameter": {"type": "string"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_xss",
            "description": "Check endpoint for reflected XSS",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "parameter": {"type": "string"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
]