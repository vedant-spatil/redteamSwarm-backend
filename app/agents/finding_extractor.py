class FindingExtractor:

    def extract(self, tool_name: str, result: dict):
        if result.get("vulnerable"):
            return {
                "severity": "HIGH",
                "tool": tool_name,
                "result": result,
            }

        return None