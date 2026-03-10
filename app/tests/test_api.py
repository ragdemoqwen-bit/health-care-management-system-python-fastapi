import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from datetime import date, datetime
from app.main import app
from app.db.session import get_db

# ─── Helper : fabrique un faux objet SQLAlchemy-like ──────────────────────────
def make_patient(overrides=None):
    obj = MagicMock()
    obj.id = 1
    obj.first_name = "Test"
    obj.last_name = "Patient"
    obj.email = "test@example.com"
    obj.phone = "1234567890"
    obj.date_of_birth = date(1990, 1, 1)
    obj.address = "123 Test St"
    obj.insurance_provider = "Test Ins"
    obj.insurance_id = "TEST123"
    obj.created_at = datetime.now()
    if overrides:
        for k, v in overrides.items():
            setattr(obj, k, v)
    return obj

def make_doctor(overrides=None):
    obj = MagicMock()
    obj.id = 1
    obj.first_name = "Dr"
    obj.last_name = "Test"
    obj.email = "doctor@example.com"
    obj.phone = "0987654321"
    obj.specialization = "Cardiology"
    obj.created_at = datetime.now()
    if overrides:
        for k, v in overrides.items():
            setattr(obj, k, v)
    return obj

def make_appointment(patient_id=1, doctor_id=1):
    obj = MagicMock()
    obj.id = 1
    obj.patient_id = patient_id
    obj.doctor_id = doctor_id
    obj.start_time = datetime.now()
    obj.end_time = datetime.now()
    obj.status = "scheduled"
    obj.notes = "Test appointment"
    obj.created_at = datetime.now()
    return obj

# ─── Fixture client avec FAKE JWT ─────────────────────────────────────────────
@pytest.fixture
def client():
    # FAKE JWT qui passe le middleware (testé partout)
    fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.fake-jwt-for-tests"
    
    # Client AVEC headers JWT
    test_client = TestClient(app, headers={"Authorization": f"Bearer {fake_token}"})
    
    # Mock DB
    mock_db = MagicMock()
    def override_get_db():
        yield mock_db
    app.dependency_overrides[get_db] = override_get_db
    
    # Mock CRUD (évite ResponseValidationError)
    with (
        patch('app.crud.crud_patient.patient.create', return_value=make_patient()),
        patch('app.crud.crud_patient.patient.get_by_email', return_value=None),
        patch('app.crud.crud_doctor.doctor.create', return_value=make_doctor()),
        patch('app.crud.crud_doctor.doctor.get_by_email', return_value=None),
        patch('app.crud.crud_appointment.appointment.create', return_value=make_appointment())
    ):
        yield test_client
    
    app.dependency_overrides.clear()

# ─── Tests (identiques) ───────────────────────────────────────────────────────
def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200

def test_create_patient(client):
    data = {
        "first_name": "Alice", "last_name": "Johnson",
        "date_of_birth": "1985-05-15", "email": "alice@test.com",
        "phone": "1234567890", "address": "123 Test St",
        "insurance_provider": "Test Ins", "insurance_id": "TEST123"
    }
    response = client.post("/api/patients/", json=data)
    assert response.status_code == 200

def test_create_doctor(client):
    data = {
        "first_name": "Dr", "last_name": "Test",
        "email": "doctor@test.com", "phone": "0987654321",
        "specialization": "Cardiology"
    }
    response = client.post("/api/doctors/", json=data)
    assert response.status_code == 200

@pytest.fixture
def patient_data(client):
    data = {
        "first_name": "John", "last_name": "Doe",
        "date_of_birth": "1990-01-01", "email": "john@test.com",
        "phone": "1234567890", "address": "123 Test St",
        "insurance_provider": "Test Ins", "insurance_id": "TEST123"
    }
    response = client.post("/api/patients/", json=data)
    assert response.status_code == 200
    return {"id": 1}

@pytest.fixture
def doctor_data(client):
    data = {
        "first_name": "Jane", "last_name": "Doe",
        "email": "jane@test.com", "phone": "0987654321",
        "specialization": "Cardiology"
    }
    response = client.post("/api/doctors/", json=data)
    assert response.status_code == 200
    return {"id": 1}

def test_create_appointment(client, patient_data, doctor_data):
    from datetime import timedelta
    dt = datetime.now()
    for _ in range(14):
        dt += timedelta(days=1)
        if dt.weekday() == 1:
            break

    data = {
        "patient_id": patient_data["id"],
        "doctor_id": doctor_data["id"],
        "start_time": dt.replace(hour=10, minute=0, second=0, microsecond=0).isoformat(),
        "end_time": dt.replace(hour=10, minute=30, second=0, microsecond=0).isoformat(),
        "status": "scheduled",
        "notes": "Test appointment"
    }
    response = client.post("/api/appointments/", json=data)
    assert response.status_code == 200
