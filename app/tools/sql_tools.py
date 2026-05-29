from app.tools.http_tools import (
    http_request
)

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "' OR 1=1--",
]

async def check_sql_injection(
    url: str,
    parameter: str,
):

    findings = []

    for payload in SQL_PAYLOADS:

        separator = "&" if "?" in url else "?"

        target = (
            f"{url}"
            f"{separator}"
            f"{parameter}={payload}"
        )

        print("[SQL TOOL] TARGET:")
        print(target)

        response = await http_request(target)

        if not response.get("success"):

            continue

        body = response.get(
            "body",
            ""
        ).lower()

        sql_errors = [
            "sql syntax",
            "mysql",
            "sqlite",
            "syntax error",
            "unclosed quotation mark",
            "odbc",
            "postgresql",
        ]

        if any(
            err in body
            for err in sql_errors
        ):

            findings.append({
                "payload": payload,
                "target": target,
            })

    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
    }
