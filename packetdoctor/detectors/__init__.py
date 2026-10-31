from .base import Detector
from .faults import FAULT_DETECTORS

try:
    from .attacks import ATTACK_DETECTORS
except ImportError:  # attack detectors are added in a later phase
    ATTACK_DETECTORS = []

ALL_DETECTORS = FAULT_DETECTORS + ATTACK_DETECTORS

__all__ = ["Detector", "ALL_DETECTORS", "FAULT_DETECTORS", "ATTACK_DETECTORS"]
