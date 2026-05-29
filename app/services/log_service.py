from sqlalchemy.orm import Session

from app.repositories.log_repository import LogRepository
from app.db.models import LogModel

class LogService:
    @staticmethod
    def log(db: Session, level: str, message: str):
        entry = LogModel(
            id=message[:10],
            level=level,
            message=message,
        )

        return LogRepository.create(db, entry)