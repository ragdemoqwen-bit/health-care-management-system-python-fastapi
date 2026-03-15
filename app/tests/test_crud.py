import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.crud import crud_patient
from app.schemas.patient import PatientCreate, PatientUpdate
from app.db.models import Patient, Base

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_crud.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture
def patient_in():
    return PatientCreate(
        first_name="Test",
        last_name="User",
        date_of_birth="1990-01-01",
        email="test.user@example.com",
        phone="1234567890",
        address="123 Test St",
        insurance_provider="Test Insurance",
        insurance_id="TI123456"
    )

def test_create_patient(test_db: Session, patient_in):
    patient_obj = crud_patient.patient.create(test_db, obj_in=patient_in)
    assert patient_obj.id is not None
    assert patient_obj.first_name == "Test"

def test_get_patient(test_db: Session, patient_in):
    created = crud_patient.patient.create(test_db, obj_in=patient_in)
    fetched = crud_patient.patient.get(test_db, id=created.id)  # ✅ FIX: id (pas patient_id)
    assert fetched.id == created.id

def test_update_patient(test_db: Session, patient_in):
    created = crud_patient.patient.create(test_db, obj_in=patient_in)
    update_data = PatientUpdate(first_name="Updated")
    updated = crud_patient.patient.update(test_db, db_obj=created, obj_in=update_data)
    assert updated.first_name == "Updated"

def test_delete_patient(test_db: Session, patient_in):
    created = crud_patient.patient.create(test_db, obj_in=patient_in)
    crud_patient.patient.delete(test_db, db_obj=created)  # ✅ FIX: delete() avec db_obj
    fetched = crud_patient.patient.get(test_db, id=created.id)  # ✅ FIX: id (pas patient_id)
    assert fetched is None
