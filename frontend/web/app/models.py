from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)


class HostReport(Base):
    __tablename__ = "host_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    target_os: Mapped[str] = mapped_column(String(64), default="Linux")
    inspection_date: Mapped[str] = mapped_column(String(64), default="")
    source_filename: Mapped[str] = mapped_column(String(512), default="")
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    diagnostics: Mapped[list[DiagnosticItem]] = relationship(
        "DiagnosticItem",
        back_populates="report",
        cascade="all, delete-orphan",
    )


class DiagnosticItem(Base):
    __tablename__ = "diagnostic_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("host_reports.id", ondelete="CASCADE"))
    code: Mapped[str] = mapped_column(String(32), default="")
    category: Mapped[str] = mapped_column(String(64), default="")
    title: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(16), default="N/A")
    severity: Mapped[str] = mapped_column(String(16), default="Medium")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    processed_config: Mapped[str] = mapped_column(Text, default="")
    raw_config: Mapped[str] = mapped_column(Text, default="")
    vulnerable_config: Mapped[str] = mapped_column(Text, default="")
    err_msg: Mapped[str] = mapped_column(Text, default="")

    report: Mapped[HostReport] = relationship("HostReport", back_populates="diagnostics")


class Guideline(Base):
    __tablename__ = "guidelines"
    __table_args__ = (UniqueConstraint("os_type", "code", name="uq_guideline_os_code"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    os_type: Mapped[str] = mapped_column(String(32), nullable=False, default="Linux")
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    pass_comment: Mapped[str] = mapped_column(Text, default="")
    fail_comment: Mapped[str] = mapped_column(Text, default="")
