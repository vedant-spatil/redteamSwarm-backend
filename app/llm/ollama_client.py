import httpx

from app.core.config import settings

class OllamaClient:
    async def chat(self, messages, tools=None):
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{settings.OLLAMA_HOST}/api/chat",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "messages": messages,
                    "tools": tools or [],
                    "stream": False,
                }
            )

            response.raise_for_status()
            return response.json()