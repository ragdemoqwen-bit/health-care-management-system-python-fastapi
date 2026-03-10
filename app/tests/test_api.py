import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from app.main import app
from app.api.deps import get_db, get_current_user, get_current_active_user

@pytest.fixture
def client():
    # Mock DB
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None
    mock_db.add.return_value = None
    mock_db.commit.return_value = None
    mock_db.refresh.return_value = None
    
    # Mock User ADMIN
    mock_user = MagicMock()
    mock_user.is_active = True
    mock_user.role = "admin"
    
    # Override TOUS les Depends
    def override_get_db(): return mock_db
    def override_get_current_user(): return mock_user
    def override_get_current_active_user(): return mock_user
    
    app.dependency_overrides = {
        get_db: override_get_db,
        get_current_user: override_get_current_user,
        get_current_active_user: override_get_current_active_user
    }
    
    yield TestClient(app)
    app.dependency_overrides.clear()

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
    return {"id": 1, **data}

@pytest.fixture
def doctor_data(client):
    data = {
        "first_name": "Jane", "last_name": "Doe",
        "email": "jane@test.com", "phone": "0987654321",
        "specialization": "Cardiology"
    }
    response = client.post("/api/doctors/", json=data)
    assert response.status_code == 200
    return {"id": 1, **data}

def test_create_appointment(client, patient_data, doctor_data):
    from datetime import datetime, timedelta
    dt = datetime.now()
    for _ in range(14):
        dt += timedelta(days=1)
        if dt.weekday() == 1: break
    
    data = {
        "patient_id": patient_data["id"],
        "doctor_id": doctor_data["id"],
        "start_time": dt.replace(hour=10).isoformat(),
        "end_time": dt.replace(hour=10, minute=30).isoformat(),
        "status": "scheduled",
        "notes": "Test appointment"
    }
    response = client.post("/api/appointments/", json=data)
    assert response.status_code == 200
