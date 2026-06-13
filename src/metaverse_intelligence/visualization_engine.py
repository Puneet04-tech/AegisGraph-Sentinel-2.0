"""
Investigation Visualization Engine
Creates immersive visualizations for fraud and crime investigation.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
import math
import random

from .models import (
    VisualizationType,
    VisualizationNode,
    VisualizationEdge,
    VisualizationScene,
    InvestigationCase,
    FraudRing,
    RiskLevel,
)


class VisualizationEngine:
    """Engine for creating investigation visualizations."""
    
    def __init__(self):
        self.scenes: Dict[str, VisualizationScene] = {}
    
    def create_network_graph(
        self,
        title: str,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ) -> VisualizationScene:
        """Create a network graph visualization."""
        scene_id = str(uuid4())
        nodes = []
        edges = []
        
        for i, entity in enumerate(entities):
            angle = 2 * math.pi * i / len(entities)
            radius = 5.0
            
            pos = (
                radius * math.cos(angle) + random.uniform(-0.5, 0.5),
                radius * math.sin(angle) + random.uniform(-0.5, 0.5),
                random.uniform(-1, 1),
            )
            
            risk = entity.get("risk_level", "LOW")
            color = self._get_risk_color(risk)
            
            node = VisualizationNode(
                node_id=entity.get("id", str(uuid4())),
                label=entity.get("name", f"Entity {i}"),
                node_type=entity.get("type", "UNKNOWN"),
                position=pos,
                size=entity.get("size", 1.0),
                color=color,
                properties=entity.get("properties", {}),
                risk_level=RiskLevel(risk) if risk in [r.value for r in RiskLevel] else RiskLevel.LOW,
            )
            nodes.append(node)
        
        for rel in relationships:
            edge = VisualizationEdge(
                edge_id=str(uuid4()),
                source_id=rel.get("source"),
                target_id=rel.get("target"),
                edge_type=rel.get("type", "RELATED"),
                weight=rel.get("weight", 1.0),
                label=rel.get("label"),
            )
            edges.append(edge)
        
        scene = VisualizationScene(
            scene_id=scene_id,
            title=title,
            visualization_type=VisualizationType.NETWORK_GRAPH,
            nodes=nodes,
            edges=edges,
        )
        
        self.scenes[scene_id] = scene
        return scene
    
    def create_3d_graph(
        self,
        title: str,
        entities: List[Dict[str, Any]],
        connections: List[Dict[str, Any]],
    ) -> VisualizationScene:
        """Create a 3D graph visualization."""
        scene_id = str(uuid4())
        nodes = []
        edges = []
        
        for i, entity in enumerate(entities):
            phi = math.acos(1 - 2 * (i + 0.5) / len(entities))
            theta = math.pi * (1 + math.sqrt(5)) * i
            
            pos = (
                10 * math.sin(phi) * math.cos(theta),
                10 * math.sin(phi) * math.sin(theta),
                10 * math.cos(phi),
            )
            
            risk = entity.get("risk_level", "LOW")
            color = self._get_risk_color(risk)
            
            node = VisualizationNode(
                node_id=entity.get("id", str(uuid4())),
                label=entity.get("name", f"Node {i}"),
                node_type=entity.get("type", "ENTITY"),
                position=pos,
                size=entity.get("size", 1.0),
                color=color,
                properties=entity.get("properties", {}),
            )
            nodes.append(node)
        
        for conn in connections:
            edge = VisualizationEdge(
                edge_id=str(uuid4()),
                source_id=conn.get("source"),
                target_id=conn.get("target"),
                edge_type=conn.get("type", "CONNECTS"),
                weight=conn.get("weight", 1.0),
            )
            edges.append(edge)
        
        scene = VisualizationScene(
            scene_id=scene_id,
            title=title,
            visualization_type=VisualizationType.GRAPH_3D,
            nodes=nodes,
            edges=edges,
            camera_position=(0, 0, 30),
        )
        
        self.scenes[scene_id] = scene
        return scene
    
    def create_timeline(
        self,
        title: str,
        events: List[Dict[str, Any]],
    ) -> VisualizationScene:
        """Create a timeline visualization."""
        scene_id = str(uuid4())
        nodes = []
        
        for i, event in enumerate(events):
            pos = (i * 2.0, 0, 0)
            
            node = VisualizationNode(
                node_id=event.get("id", str(uuid4())),
                label=event.get("title", f"Event {i}"),
                node_type="EVENT",
                position=pos,
                size=1.0,
                color="#3498db",
                properties=event.get("properties", {}),
            )
            nodes.append(node)
        
        edges = []
        for i in range(len(nodes) - 1):
            edges.append(VisualizationEdge(
                edge_id=str(uuid4()),
                source_id=nodes[i].node_id,
                target_id=nodes[i + 1].node_id,
                edge_type="SEQUENCE",
            ))
        
        scene = VisualizationScene(
            scene_id=scene_id,
            title=title,
            visualization_type=VisualizationType.TIMELINE,
            nodes=nodes,
            edges=edges,
        )
        
        self.scenes[scene_id] = scene
        return scene
    
    def create_heatmap(
        self,
        title: str,
        data: Dict[str, float],
    ) -> VisualizationScene:
        """Create a heatmap visualization."""
        scene_id = str(uuid4())
        nodes = []
        
        size = int(math.ceil(math.sqrt(len(data))))
        
        for i, (key, value) in enumerate(data.items()):
            row = i // size
            col = i % size
            
            pos = (col * 2.0, -row * 2.0, 0)
            
            intensity = min(1.0, value / 100)
            color = self._get_heatmap_color(intensity)
            
            node = VisualizationNode(
                node_id=str(uuid4()),
                label=key,
                node_type="HEATMAP_CELL",
                position=pos,
                size=1.0 + intensity * 2,
                color=color,
                properties={"value": value, "intensity": intensity},
            )
            nodes.append(node)
        
        scene = VisualizationScene(
            scene_id=scene_id,
            title=title,
            visualization_type=VisualizationType.HEATMAP,
            nodes=nodes,
            edges=[],
        )
        
        self.scenes[scene_id] = scene
        return scene
    
    def get_scene(self, scene_id: str) -> Optional[VisualizationScene]:
        """Get a scene by ID."""
        return self.scenes.get(scene_id)
    
    def _get_risk_color(self, risk: str) -> str:
        """Get color for risk level."""
        colors = {
            "CRITICAL": "#e74c3c",
            "HIGH": "#e67e22",
            "MEDIUM": "#f1c40f",
            "LOW": "#2ecc71",
            "MINIMAL": "#3498db",
        }
        return colors.get(risk, "#95a5a6")
    
    def _get_heatmap_color(self, intensity: float) -> str:
        """Get heatmap color for intensity."""
        if intensity < 0.25:
            return "#2ecc71"
        elif intensity < 0.5:
            return "#f1c40f"
        elif intensity < 0.75:
            return "#e67e22"
        else:
            return "#e74c3c"


def get_visualization_engine() -> VisualizationEngine:
    """Get the global visualization engine instance."""
    global _visualization_engine
    if _visualization_engine is None:
        _visualization_engine = VisualizationEngine()
    return _visualization_engine


_visualization_engine: Optional[VisualizationEngine] = None