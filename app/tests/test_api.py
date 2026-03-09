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

# ------------------- CONFIG DB DE TEST -------------------
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ------------------- OVERRIDE get_db -------------------
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

# ------------------- FIXTURE DB -------------------
@pytest.fixture(scope="module", autouse=True)
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

# ------------------- FIXTURE ADMIN TOKEN -------------------
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

# ------------------- FIXTURE PATIENT -------------------
@pytest.fixture(scope="module")
def patient_data(test_db, admin_token):
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1990-01-01",
        "email": "john.doe@example.com",
        "phone": "1234567890",
        "address": "123 Main St",
        "insurance_provider": "Blue Cross",
        "insurance_id": "BC123456"
    }
    response = client.post(
        "/api/patients/",
        json=data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    return response.json()

# ------------------- FIXTURE DOCTOR -------------------
@pytest.fixture(scope="module")
def doctor_data(test_db, admin_token):
    data = {
        "first_name": "Jane",
        "last_name": "Smith",
        "email": "jane.smith@example.com",
        "phone": "0987654321",
        "specialization": "Cardiology"
    }
    response = client.post(
        "/api/doctors/",
        json=data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    doctor_id = response.json()["id"]
    availability_data = {
        "day_of_week": 1,
        "start_time": "09:00:00",
        "end_time": "17:00:00",
        "is_available": True
    }
    client.post(
        f"/api/doctors/{doctor_id}/availability",
        json=availability_data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    return response.json()

# ------------------- TESTS API -------------------
def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_create_patient(admin_token):
    data = {
        "first_name": "Alice",
        "last_name": "Johnson",
        "date_of_birth": "1985-05-15",
        "email": "alice.johnson@example.com",
        "phone": "5551234567",
        "address": "456 Oak St",
        "insurance_provider": "Aetna",
        "insurance_id": "AE789012"
    }
    response = client.post(
        "/api/patients/",
        json=data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["first_name"] == data["first_name"]

def test_create_doctor(admin_token):
    data = {
        "first_name": "Robert",
        "last_name": "Williams",
        "email": "robert.williams@example.com",
        "phone": "5559876543",
        "specialization": "Neurology"
    }
    response = client.post(
        "/api/doctors/",
        json=data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["specialization"] == data["specialization"]

def test_create_appointment(admin_token, patient_data, doctor_data):
    # Prochain mardi
    dt = datetime.now() + timedelta(days=1)
    while dt.weekday() != 1:
        dt += timedelta(days=1)

    start_time = dt.replace(hour=10, minute=0, second=0, microsecond=0)
    end_time = dt.replace(hour=10, minute=30, second=0, microsecond=0)

    appointment = {
        "patient_id": patient_data["id"],
        "doctor_id": doctor_data["id"],
        "start_time": start_time,  # datetime object direct
        "end_time": end_time,      # datetime object direct
        "status": "scheduled",
        "notes": "Regular checkup"
    }
    # FastAPI / Pydantic accepte maintenant un datetime objet pour le test
    response = client.post(
        "/api/appointments/",
        json={
            **appointment,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        },
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == appointment["status"]