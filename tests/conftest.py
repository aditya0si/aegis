"""AEGIS tests conftest."""
import pytest
from fastapi.testclient import TestClient
from aegis.proxy.app import create_app
from aegis.config import default_policy
from aegis.analyzer.store import clear_db

@pytest.fixture
def policy():
    return default_policy()

@pytest.fixture
def app(policy):
    return create_app(policy=policy)

@pytest.fixture
def client(app):
    return TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    clear_db()
    yield
    clear_db()
