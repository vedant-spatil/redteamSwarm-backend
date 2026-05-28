from sqlalchemy import Column, String, Boolean, Text

from app.db.database import Base


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    severity = Column(String)
    vuln_type = Column(String)
    description = Column(Text)
    url = Column(String)
    confirmed = Column(Boolean, default=False)


class ForumModel(Base):
    __tablename__ = "forum"

    id = Column(String, primary_key=True)
    agent_id = Column(String)
    message = Column(Text)


class LogModel(Base):
    __tablename__ = "logs"

    id = Column(String, primary_key=True)
    level = Column(String)
    message = Column(Text)