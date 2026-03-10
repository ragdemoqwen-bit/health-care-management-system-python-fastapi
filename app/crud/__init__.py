"""
CRUD package.
"""
from .crud_base import CRUDBase  # ← Nom exact de ton fichier
from .crud_patient import patient

__all__ = ["CRUDBase", "patient"]
