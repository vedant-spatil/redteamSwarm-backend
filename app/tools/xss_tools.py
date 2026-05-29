from app.tools.http_tools import (
    http_request
)

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
]

async def check_xss(
    url: str,
    parameter: str,
):

    findings = []

    for payload in XSS_PAYLOADS:

        separator = "&" if "?" in url else "?"

        target = (
            f"{url}"
            f"{separator}"
            f"{parameter}={payload}"
        )

        print("[XSS TOOL] TARGET:")
        print(target)

        response = await http_request(target)

        if not response.get("success"):

            continue

        body = response.get(
            "body",
            ""
        )

        if payload in body:

            findings.append({
                "payload": payload,
                "target": target,
            })

    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
    }
