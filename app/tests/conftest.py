import pytest
from unittest.mock import Mock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.main import app
from app.api.deps import get_db

@pytest.fixture(scope="module")
def client():
    # Mock get_db pour API tests
    def override_get_db():
        db = Mock(spec=Session)
        db.query.return_value.filter.return_value.first.return_value = None
        db.add = Mock()
        db.commit = Mock()
        db.refresh = Mock()
        db.delete = Mock()
        return db
    
    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()
