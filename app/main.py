from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import swarm
from app.api.routes import findings
from app.api.routes import forum
from app.api.routes import agents
from app.api.routes import health

from app.core.logging import setup_logging
from app.db.database import Base, engine


setup_logging()

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Red Team Swarm",
)

app.add_middleware( 
    CORSMiddleware, 
    allow_origins=["*"],
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"], 
)

app.include_router(swarm.router)
app.include_router(findings.router)
app.include_router(forum.router)
app.include_router(agents.router)
app.include_router(health.router)