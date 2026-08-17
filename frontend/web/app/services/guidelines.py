from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import GUIDELINES_SEED
from app.models import Guideline


def seed_guidelines(db: Session) -> None:
    """Insert seed guidelines; also backfill missing (os_type, code) pairs."""
    path = Path(GUIDELINES_SEED)
    if not path.exists():
        return
    items = json.loads(path.read_text(encoding="utf-8"))
    existing = {
        (g.os_type, g.code)
        for g in db.query(Guideline.os_type, Guideline.code).all()
    }
    added = 0
    for item in items:
        os_type = item.get("os_type", "Linux")
        code = item.get("code", "")
        if not code or (os_type, code) in existing:
            continue
        db.add(
            Guideline(
                os_type=os_type,
                code=code,
                title=item.get("title", ""),
                remediation=item.get("remediation", ""),
                pass_comment=item.get("pass_comment", ""),
                fail_comment=item.get("fail_comment", ""),
            )
        )
        added += 1
    if added or db.query(Guideline).count() == 0:
        db.commit()


def guidelines_as_dicts(db: Session) -> list[dict[str, Any]]:
    rows = db.query(Guideline).all()
    return [
        {
            "os_type": g.os_type,
            "code": g.code,
            "title": g.title,
            "remediation": g.remediation,
            "pass_comment": g.pass_comment,
            "fail_comment": g.fail_comment,
        }
        for g in rows
    ]


def list_guidelines(db: Session, os_type: str = "Linux") -> list[Guideline]:
    return (
        db.query(Guideline)
        .filter(Guideline.os_type == os_type)
        .order_by(Guideline.code)
        .all()
    )


def update_guideline(
    db: Session,
    guideline_id: int,
    *,
    title: str,
    remediation: str,
    pass_comment: str,
    fail_comment: str,
) -> Guideline | None:
    row = db.query(Guideline).filter(Guideline.id == guideline_id).first()
    if row is None:
        return None
    row.title = title
    row.remediation = remediation
    row.pass_comment = pass_comment
    row.fail_comment = fail_comment
    db.commit()
    db.refresh(row)
    return row
