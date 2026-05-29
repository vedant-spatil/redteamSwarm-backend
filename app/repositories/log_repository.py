from sqlalchemy.orm import Session

from app.db.models import LogModel

class LogRepository:
    @staticmethod
    def create(db: Session, log: LogModel):
        db.add(log)
        db.commit()
        db.refresh(log)
        return log