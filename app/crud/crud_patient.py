# app/crud/crud_patient.py

from typing import Optional
from sqlalchemy.orm import Session
from app.db.models import Patient
from app.schemas.patient import PatientCreate, PatientUpdate

class CRUDPatient:
    """CRUD pour le modèle Patient"""

    def get(self, db: Session, patient_id: int) -> Optional[Patient]:
        """Retourne un patient par ID"""
        return db.query(Patient).filter(Patient.id == patient_id).first()

    def get_by_email(self, db: Session, *, email: str) -> Optional[Patient]:
        """Retourne un patient par email"""
        return db.query(Patient).filter(Patient.email == email).first()

    def get_all(self, db: Session) -> list[Patient]:
        """Retourne tous les patients"""
        return db.query(Patient).all()

    def create(self, db: Session, obj_in: PatientCreate) -> Patient:
        """Crée un nouveau patient"""
        db_obj = Patient(**obj_in.model_dump())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def update(self, db: Session, db_obj: Patient, obj_in: PatientUpdate) -> Patient:
        """Met à jour un patient existant"""
        obj_data = obj_in.model_dump(exclude_unset=True)
        for field, value in obj_data.items():
            setattr(db_obj, field, value)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def remove(self, db: Session, patient_id: int) -> Patient:
        """Supprime un patient"""
        obj = db.query(Patient).get(patient_id)
        if obj:
            db.delete(obj)
            db.commit()
        return obj

# Instancier le CRUD pour l'import dans les routes
patient = CRUDPatient()