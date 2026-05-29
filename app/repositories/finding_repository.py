from sqlalchemy.orm import Session

from app.db.models import FindingModel

class FindingRepository:
    @staticmethod
    def get_all(db: Session):
        return db.query(FindingModel).all()

    @staticmethod
    def create(db: Session, finding: FindingModel):
        db.add(finding)
        db.commit()
        db.refresh(finding)
        return finding