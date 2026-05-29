from pydantic import BaseModel

class Finding(BaseModel):
    severity: str
    vuln_type: str
    description: str
    url: str
    confirmed: bool = False