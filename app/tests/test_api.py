import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from app.main import app
from app.api.deps import get_db, get_current_user, get_current_active_user
from app.schemas.patient import PatientCreate
from app.db.models import Patient
from datetime import datetime

@pytest.fixture
def client():
    # Mock User ADMIN
    mock_user = MagicMock()
    mock_user.is_active = True
    mock_user.role = "admin"
    
    # Mock DB avec RETOUR Patient/Doctor complet
    mock_patient = MagicMock(spec=Patient)
    mock_patient.id = 1
    mock_patient.created_at = datetime.now()
    mock_patient.first_name = "Test"
    mock_patient.email = "test@test.com"
    
    mock_doctor = MagicMock(spec=Patient)  # Réutilisé pour doctor
    mock_doctor.id = 1
    mock_doctor.created_at = datetime.now()
    
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None
    mock_db.add.return_value = None
    mock_db.commit.return_value = None
    mock_db.refresh.return_value = None
    
    # ✅ CRITIQUE : Mock crud.create() retourne objet complet
    with patch('app.crud.crud_patient.patient.create') as mock_create_patient, \
         patch('app.crud.crud_doctor.doctor.create') as mock_create_doctor:
        mock_create_patient.return_value = mock_patient
        mock_create_doctor.return_value = mock_doctor
        
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
    assert response.json()["id"] == 1

def test_create_doctor(client):
    data = {
        "first_name": "Dr", "last_name": "Test",
        "email": "doctor@test.com", "phone": "0987654321",
        "specialization": "Cardiology"
    }
    response = client.post("/api/doctors/", json=data)
    assert response.status_code == 200
    assert response.json()["id"] == 1

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
    return {"id": 1, "email": "john@test.com"}

@pytest.fixture
def doctor_data(client):
    data = {
        "first_name": "Jane", "last_name": "Doe",
        "email": "jane@test.com", "phone": "0987654321",
        "specialization": "Cardiology"
    }
    response = client.post("/api/doctors/", json=data)
    assert response.status_code == 200
    return {"id": 1, "email": "jane@test.com"}

def test_create_appointment(client, patient_data, doctor_data):
    from datetime import datetime, timedelta
    dt = datetime.now()
    for _ in range(14):
        dt += timedelta(days=1)
        if dt.weekday() == 1: break
    
    data = {
        "patient_id": 1, "doctor_id": 1,
        "start_time": dt.replace(hour=10).isoformat(),
        "end_time": dt.replace(hour=10, minute=30).isoformat(),
        "status": "scheduled"
    }
    response = client.post("/api/appointments/", json=data)
    assert response.status_code == 200
