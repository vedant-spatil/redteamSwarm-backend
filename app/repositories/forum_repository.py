from sqlalchemy.orm import Session

from app.db.models import ForumModel

class ForumRepository:
    @staticmethod
    def create(db: Session, entry: ForumModel):
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @staticmethod
    def get_recent(db: Session):
        return db.query(ForumModel).all()