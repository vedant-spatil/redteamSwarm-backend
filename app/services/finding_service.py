from sqlalchemy.orm import Session

from app.repositories.finding_repository import FindingRepository

class FindingService:
    @staticmethod
    def get_findings(db: Session):
        return FindingRepository.get_all(db)