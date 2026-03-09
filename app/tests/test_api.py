import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

from app.main import app
from app.db.models import Base
from app.db.session import get_db
from app.crud.crud_user import user
from app.schemas.user import UserCreate, UserRole

# ---------------- DB de test ----------------
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override get_db pour tests
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

# ---------------- Fixtures ----------------
@pytest.fixture(scope="module")
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="module")
def admin_token(test_db):
    db = TestingSessionLocal()
    admin_user = UserCreate(
        email="admin@example.com",
        username="admin",
        password="password",
        role=UserRole.ADMIN
    )
    user.create(db, obj_in=admin_user)
    db.close()

    response = client.post(
        "/api/auth/login",
        json={"email": "admin@example.com", "password": "password"}
    )
    return response.json()["access_token"]

# ---------------- Tests ----------------
def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"