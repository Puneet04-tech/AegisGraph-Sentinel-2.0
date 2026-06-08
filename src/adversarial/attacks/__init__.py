"""Adversarial attack implementations."""
from .structural import EdgeAddition, EdgeDeletion, NodeInjection, DecoyNodeInjection
from .feature import FeaturePerturbation

__all__ = ["EdgeAddition", "EdgeDeletion", "NodeInjection", "FeaturePerturbation", "DecoyNodeInjection"]