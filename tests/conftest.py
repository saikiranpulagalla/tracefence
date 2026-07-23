from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from tracefence.db.engine import build_engine, init_db


@pytest.fixture
def session_factory(tmp_path) -> sessionmaker:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'test.db'}"
    engine = build_engine(database_url)
    init_db(engine)
    factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
    yield factory
    engine.dispose()
