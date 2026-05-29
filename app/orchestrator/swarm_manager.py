import asyncio

from app.agents.autonomous_agent import (
    AutonomousAgent
)

from app.agents.focus_areas import (
    FOCUS_AREAS
)


class SwarmManager:

    def __init__(self):

        self.agents = []
        self.tasks = []

        self.findings = []

        self.running = False

    async def start(
        self,
        target_url: str,
        count: int
    ):

        self.running = True

        self.findings.clear()

        self.agents.clear()
        self.tasks.clear()

        for i in range(count):

            focus = (
                FOCUS_AREAS[
                    i % len(FOCUS_AREAS)
                ]
            )

            agent = AutonomousAgent(
                target_url=target_url,
                focus_area=focus,
            )

            task = asyncio.create_task(
                agent.run()
            )

            self.agents.append(agent)
            self.tasks.append(task)

    async def stop(self):

        self.running = False

        for agent in self.agents:
            agent.running = False

        for task in self.tasks:
            task.cancel()

        self.agents.clear()
        self.tasks.clear()


swarm_manager = SwarmManager()