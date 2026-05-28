import asyncio
import httpx

async def http_request(
    url: str,
    method: str = "GET",
):

    retries = 3

    for attempt in range(retries):

        try:

            print(f"[HTTP TOOL] REQUEST:")
            print(method, url)

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(
                    30.0,
                    connect=10.0,
                ),
                follow_redirects=True,
                verify=False,
            ) as client:

                response = await client.request(
                    method,
                    url,
                    headers={
                        "User-Agent":
                        "Mozilla/5.0"
                    }
                )

                print(f"[HTTP TOOL] RESPONSE:")
                print(response.status_code)

                return {
                    "success": True,
                    "status": response.status_code,
                    "body": response.text[:5000],
                }

        except Exception as e:

            print("[HTTP TOOL] ERROR:")
            print(repr(e))

            if attempt < retries - 1:

                print(
                    f"[HTTP TOOL] RETRY {attempt + 1}"
                )

                await asyncio.sleep(2)

            else:

                return {
                    "success": False,
                    "error": str(e),
                }
