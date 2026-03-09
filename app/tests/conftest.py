# tests/setup_test_db.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import date, datetime

from app.database import Base, get_db
from app.models import Doctor, Patient, User  # importe tes modèles

# --- Créer une DB SQLite en mémoire pour les tests ---
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- Fixture pytest pour avoir une session DB propre à chaque test ---
@pytest.fixture(scope="function")
def db():
    # Créer toutes les tables avant le test
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Optionnel : vider les tables après chaque test
        Base.metadata.drop_all(bind=engine)

# --- Exemple de test doctor corrigé pour dates et SQLite ---
def test_create_doctor(db):
    from app.schemas import DoctorCreate
    from app.crud import doctor

    doctor_in = DoctorCreate(
        first_name="Test",
        last_name="Doctor",
        email="test.doctor@example.com",
        phone="0987654321",
        specialization="Test Specialty"
    )
    doctor_obj = doctor.create(db, obj_in=doctor_in)
    assert doctor_obj.id is not None
    assert doctor_obj.first_name == "Test"

# --- Exemple de test patient avec date correcte ---
def test_create_patient(db):
    from app.schemas import PatientCreate
    from app.crud import patient

    patient_in = PatientCreate(
        first_name="Appointment",
        last_name="Patient",
        date_of_birth=date(1990, 1, 1),  # <-- date correcte
        email="appointment.patient@example.com",
        phone="1234567890",
        address="123 Test St",
        insurance_provider="Test Insurance",
        insurance_id="TI123456"
    )
    patient_obj = patient.create(db, obj_in=patient_in)
    assert patient_obj.id is not None
    assert patient_obj.date_of_birth == date(1990, 1, 1)