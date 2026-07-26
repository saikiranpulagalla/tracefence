from __future__ import annotations

import os

# Ordinary tests must not depend on whether the host scheduler pauses longer
# than the production lease. Expiry tests set authoritative timestamps into the
# past; production and live validation retain the seven-second default.
os.environ["TRACEFENCE_ENV"] = "test"
os.environ["TRACEFENCE_LEASE_TTL_SECONDS"] = "300"
os.environ["TRACEFENCE_SPAWN_INTENT_TTL_SECONDS"] = "300"

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
