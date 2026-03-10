import pytest
from unittest.mock import Mock, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.main import app
from app.api.deps import get_db

@pytest.fixture(scope="function")
def client():
    """Client avec DB mocké pour TOUS les tests API."""
    
    # Mock Session COMPLET
    class MockSession:
        def query(self, model):
            class MockQuery:
                def filter(self, *args, **kwargs):
                    class MockFilter:
                        def first(self):
                            return None  # Pas de doublon email
                    return MockFilter()
            return MockQuery()
        
        def add(self, obj): pass
        def commit(self): pass
        def refresh(self, obj): pass
        def delete(self, obj): pass
        def close(self): pass
    
    def override_get_db():
        return MockSession()
    
    # Override IMMÉDIAT
    app.dependency_overrides[get_db] = override_get_db
    
    test_client = TestClient(app)
    yield test_client
    
    # Cleanup
    app.dependency_overrides.clear()
