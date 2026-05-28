from sqlalchemy.orm import Session

from app.repositories.forum_repository import ForumRepository
from app.db.models import ForumModel

class ForumService:
    @staticmethod
    def post_message(db: Session, agent_id: str, message: str):
        entry = ForumModel(
            id=agent_id,
            agent_id=agent_id,
            message=message,
        )
        return ForumRepository.create(db, entry)