#!/usr/bin/env python3
"""
Visual API Mapping Module for VAmPI API Discovery Agent

This module generates graphical representations of API structure including:
- Endpoint relationship graphs
- Security risk heatmaps
- Authentication flow diagrams
- API structure maps
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
import seaborn as sns
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
import os
from pathlib import Path
import json

# Import models for type hints
import sys
import os
sys.path.append(os.path.dirname(__file__))

from models import EndpointMetadata, RiskLevel, AuthenticationType, HTTPMethod

# Configure matplotlib for better output
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for server environments
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class APIVisualizer:
    """
    Generates visual representations of API structure and relationships.
    
    This class creates various types of visualizations:
    - Endpoint relationship graphs
    - Security risk heatmaps
    - Authentication flow diagrams
    - API structure maps
    """
    
    def __init__(self, output_dir: str = "visualizations"):
        """
        Initialize the visualizer with output directory.
        
        Args:
            output_dir: Directory to save generated visualizations
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Color schemes for different risk levels
        self.risk_colors = {
            RiskLevel.LOW: '#2E8B57',      # Sea Green
            RiskLevel.MEDIUM: '#FFA500',   # Orange
            RiskLevel.HIGH: '#FF4500',     # Orange Red
            RiskLevel.CRITICAL: '#DC143C'  # Crimson
        }
        
        # Color schemes for authentication types
        self.auth_colors = {
            AuthenticationType.NONE: '#808080',      # Gray
            AuthenticationType.BASIC: '#4169E1',     # Royal Blue
            AuthenticationType.BEARER: '#32CD32',    # Lime Green
            AuthenticationType.JWT: '#FF69B4',       # Hot Pink
            AuthenticationType.SESSION: '#9370DB',   # Medium Purple
            AuthenticationType.API_KEY: '#FFD700',   # Gold
            AuthenticationType.OAUTH2: '#00CED1',    # Dark Turquoise
            AuthenticationType.CUSTOM: '#FF1493'     # Deep Pink
        }
        
        # HTTP method colors
        self.method_colors = {
            HTTPMethod.GET: '#4CAF50',      # Green
            HTTPMethod.POST: '#2196F3',     # Blue
            HTTPMethod.PUT: '#FF9800',      # Orange
            HTTPMethod.DELETE: '#F44336',   # Red
            HTTPMethod.PATCH: '#9C27B0',    # Purple
            HTTPMethod.HEAD: '#607D8B',     # Blue Grey
            HTTPMethod.OPTIONS: '#795548'   # Brown
        }
    
    def generate_endpoint_graph(self, endpoints: List[EndpointMetadata]) -> str:
        """
        Generate an endpoint relationship graph.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Path to generated graph image
        """
        # Create directed graph
        G = nx.DiGraph()
        
        # Add nodes (endpoints)
        for endpoint in endpoints:
            G.add_node(endpoint.path, 
                      risk_level=endpoint.risk_level,
                      auth_required=endpoint.authentication_required,
                      methods=endpoint.methods)
        
        # Add edges based on logical relationships
        for endpoint in endpoints:
            path = endpoint.path
            
            # Add relationships based on path hierarchy
            if '/' in path[1:]:  # Skip root path
                parent = '/' + '/'.join(path.split('/')[1:-1])
                if parent and parent != path:
                    G.add_edge(parent, path)
            
            # Add relationships for parameterized endpoints
            if '{' in path:
                base_path = path.split('{')[0].rstrip('/')
                if base_path and base_path != path:
                    G.add_edge(base_path, path)
        
        # Create the visualization
        plt.figure(figsize=(16, 12))
        
        # Position nodes using hierarchical layout
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Draw nodes with different colors based on risk level
        node_colors = []
        for node in G.nodes():
            # Get risk level from node attributes, with fallback
            risk_level = G.nodes[node].get('risk_level', RiskLevel.MEDIUM)
            color = self.risk_colors.get(risk_level, '#808080')
            node_colors.append(color)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, alpha=0.3, edge_color='gray', arrows=True)
        
        # Draw nodes
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1000, alpha=0.8)
        
        # Draw labels
        nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold')
        
        # Create legend for risk levels
        legend_elements = [mpatches.Patch(color=color, label=f'{level.value} Risk') 
                          for level, color in self.risk_colors.items()]
        plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))
        
        plt.title('VAmPI API Endpoint Relationship Graph', fontsize=16, fontweight='bold')
        plt.axis('off')
        
        # Save the graph
        output_path = self.output_dir / "endpoint_relationship_graph.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        return str(output_path)
    
    def generate_risk_heatmap(self, endpoints: List[EndpointMetadata]) -> str:
        """
        Generate a security risk heatmap.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Path to generated heatmap image
        """
        # Prepare data for heatmap
        risk_data = {}
        method_data = {}
        
        for endpoint in endpoints:
            # Count endpoints by risk level
            risk_level = endpoint.risk_level.value if hasattr(endpoint.risk_level, 'value') else str(endpoint.risk_level)
            risk_data[risk_level] = risk_data.get(risk_level, 0) + 1
            
            # Count HTTP methods by risk level
            if risk_level not in method_data:
                method_data[risk_level] = {}
            
            for method in endpoint.methods:
                method_value = method.value if hasattr(method, 'value') else str(method)
                method_data[risk_level][method_value] = method_data[risk_level].get(method_value, 0) + 1
        
        # Create subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
        
        # Risk level distribution pie chart
        risk_levels = list(risk_data.keys())
        risk_counts = list(risk_data.values())
        risk_colors = [self.risk_colors.get(RiskLevel(level), '#808080') for level in risk_levels]
        
        ax1.pie(risk_counts, labels=risk_levels, colors=risk_colors, autopct='%1.1f%%', 
                startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
        ax1.set_title('Endpoint Distribution by Risk Level', fontsize=14, fontweight='bold')
        
        # HTTP methods by risk level heatmap
        method_matrix = []
        method_labels = []
        
        for risk_level in risk_levels:
            row = []
            for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                count = method_data.get(risk_level, {}).get(method, 0)
                row.append(count)
            method_matrix.append(row)
            method_labels.append(risk_level)
        
        # Create heatmap
        sns.heatmap(method_matrix, 
                   xticklabels=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
                   yticklabels=method_labels,
                   annot=True, 
                   fmt='d',
                   cmap='YlOrRd',
                   ax=ax2,
                   cbar_kws={'label': 'Number of Endpoints'})
        
        ax2.set_title('HTTP Methods by Risk Level', fontsize=14, fontweight='bold')
        ax2.set_xlabel('HTTP Methods', fontsize=12, fontweight='bold')
        ax2.set_ylabel('Risk Levels', fontsize=12, fontweight='bold')
        
        plt.tight_layout()
        
        # Save the heatmap
        output_path = self.output_dir / "security_risk_heatmap.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        return str(output_path)
    
    def generate_authentication_flow(self, endpoints: List[EndpointMetadata]) -> str:
        """
        Generate an authentication flow diagram.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Path to generated flow diagram
        """
        # Group endpoints by authentication type
        auth_groups = {}
        for endpoint in endpoints:
            auth_type = endpoint.authentication_type
            if auth_type not in auth_groups:
                auth_groups[auth_type] = []
            auth_groups[auth_type].append(endpoint)
        
        # Create the visualization
        fig, ax = plt.subplots(figsize=(16, 10))
        
        # Position groups in a circular layout
        num_groups = len(auth_groups)
        angles = [i * 2 * 3.14159 / num_groups for i in range(num_groups)]
        
        # Draw authentication type groups
        for i, (auth_type, group_endpoints) in enumerate(auth_groups.items()):
            angle = angles[i]
            x = 0.7 * np.cos(angle)
            y = 0.7 * np.sin(angle)
            
            # Draw group circle
            circle = plt.Circle((x, y), 0.15, 
                              color=self.auth_colors.get(auth_type, '#808080'),
                              alpha=0.8)
            ax.add_patch(circle)
            
            # Add authentication type label
            ax.text(x, y, auth_type.value.replace('_', '\n'), 
                   ha='center', va='center', fontsize=10, fontweight='bold',
                   color='white')
            
            # Add endpoint count
            ax.text(x, y - 0.25, f'{len(group_endpoints)} endpoints', 
                   ha='center', va='center', fontsize=8, color='black')
            
            # Draw endpoints around the group
            for j, endpoint in enumerate(group_endpoints[:5]):  # Limit to 5 for readability
                ep_angle = angle + (j - 2) * 0.3
                ep_x = 0.4 * np.cos(ep_angle)
                ep_y = 0.4 * np.sin(ep_angle)
                
                # Draw endpoint dot
                risk_level = endpoint.risk_level if hasattr(endpoint.risk_level, 'value') else RiskLevel.MEDIUM
                ep_circle = plt.Circle((ep_x, ep_y), 0.02, 
                                     color=self.risk_colors.get(risk_level, '#808080'))
                ax.add_patch(ep_circle)
                
                # Add endpoint path (shortened)
                path_short = endpoint.path.split('/')[-1] if endpoint.path != '/' else '/'
                ax.text(ep_x, ep_y - 0.05, path_short, 
                       ha='center', va='center', fontsize=6, rotation=45)
                
                # Draw connection line
                ax.plot([x, ep_x], [y, ep_y], 'k-', alpha=0.3, linewidth=0.5)
        
        # Create legend
        legend_elements = [mpatches.Patch(color=color, label=f'{auth_type.value}') 
                          for auth_type, color in self.auth_colors.items()]
        ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(1.15, 1))
        
        # Set plot properties
        ax.set_xlim(-1, 1)
        ax.set_ylim(-1, 1)
        ax.set_aspect('equal')
        ax.axis('off')
        
        plt.title('VAmPI API Authentication Flow Diagram', fontsize=16, fontweight='bold')
        
        # Save the flow diagram
        output_path = self.output_dir / "authentication_flow_diagram.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        return str(output_path)
    
    def generate_api_structure_map(self, endpoints: List[EndpointMetadata]) -> str:
        """
        Generate a comprehensive API structure map.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Path to generated structure map
        """
        # Group endpoints by functionality
        functional_groups = {
            'User Management': [],
            'Book Management': [],
            'System': [],
            'Administrative': [],
            'Documentation': []
        }
        
        for endpoint in endpoints:
            path = endpoint.path.lower()
            if 'user' in path:
                functional_groups['User Management'].append(endpoint)
            elif 'book' in path:
                functional_groups['Book Management'].append(endpoint)
            elif path in ['/', '/createdb', '/health', '/status', '/info']:
                functional_groups['System'].append(endpoint)
            elif 'admin' in path:
                functional_groups['Administrative'].append(endpoint)
            elif path in ['/docs', '/swagger', '/openapi.json', '/openapi.yaml']:
                functional_groups['Documentation'].append(endpoint)
            else:
                functional_groups['System'].append(endpoint)
        
        # Create the visualization
        fig, ax = plt.subplots(figsize=(18, 12))
        
        # Position groups in a grid layout
        group_positions = {
            'User Management': (0, 2),
            'Book Management': (0, -2),
            'System': (2, 0),
            'Administrative': (-2, 0),
            'Documentation': (0, 0)
        }
        
        # Draw functional groups
        for group_name, (x, y) in group_positions.items():
            group_endpoints = functional_groups[group_name]
            
            # Draw group box
            rect = mpatches.Rectangle((x-1.5, y-1), 3, 2, 
                                    linewidth=2, 
                                    edgecolor='black',
                                    facecolor='lightblue',
                                    alpha=0.7)
            ax.add_patch(rect)
            
            # Add group title
            ax.text(x, y + 0.8, group_name, 
                   ha='center', va='center', fontsize=12, fontweight='bold')
            
            # Add endpoint count
            ax.text(x, y + 0.4, f'{len(group_endpoints)} endpoints', 
                   ha='center', va='center', fontsize=10)
            
            # Draw endpoints within the group
            for i, endpoint in enumerate(group_endpoints[:6]):  # Limit to 6 for readability
                ep_x = x - 1.2 + (i % 3) * 0.8
                ep_y = y - 0.5 + (i // 3) * 0.4
                
                # Draw endpoint dot
                risk_level = endpoint.risk_level if hasattr(endpoint.risk_level, 'value') else RiskLevel.MEDIUM
                ep_circle = plt.Circle((ep_x, ep_y), 0.05, 
                                     color=self.risk_colors.get(risk_level, '#808080'))
                ax.add_patch(ep_circle)
                
                # Add endpoint path (shortened)
                path_short = endpoint.path.split('/')[-1] if endpoint.path != '/' else '/'
                ax.text(ep_x, ep_y - 0.08, path_short, 
                       ha='center', va='center', fontsize=6, rotation=45)
        
        # Create legend for risk levels
        legend_elements = [mpatches.Patch(color=color, label=f'{level.value} Risk') 
                          for level, color in self.risk_colors.items()]
        ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1.02, 1))
        
        # Set plot properties
        ax.set_xlim(-4, 4)
        ax.set_ylim(-4, 4)
        ax.set_aspect('equal')
        ax.axis('off')
        
        plt.title('VAmPI API Structure Map', fontsize=18, fontweight='bold')
        
        # Save the structure map
        output_path = self.output_dir / "api_structure_map.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        return str(output_path)
    
    def generate_all_visualizations(self, endpoints: List[EndpointMetadata]) -> Dict[str, str]:
        """
        Generate all available visualizations.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Dictionary mapping visualization names to file paths
        """
        print("🎨 Generating Visual API Maps...")
        print(f"  📊 Processing {len(endpoints)} endpoints...")
        
        visualizations = {}
        
        try:
            # Generate endpoint relationship graph
            print("  📊 Creating endpoint relationship graph...")
            visualizations['endpoint_graph'] = self.generate_endpoint_graph(endpoints)
            print(f"    ✅ Endpoint graph saved to: {visualizations['endpoint_graph']}")
            
            # Generate security risk heatmap
            print("  🔥 Creating security risk heatmap...")
            visualizations['risk_heatmap'] = self.generate_risk_heatmap(endpoints)
            print(f"    ✅ Risk heatmap saved to: {visualizations['risk_heatmap']}")
            
            # Generate authentication flow diagram
            print("  🔐 Creating authentication flow diagram...")
            visualizations['auth_flow'] = self.generate_authentication_flow(endpoints)
            print(f"    ✅ Auth flow diagram saved to: {visualizations['auth_flow']}")
            
            # Generate API structure map
            print("  🗺️ Creating API structure map...")
            visualizations['structure_map'] = self.generate_api_structure_map(endpoints)
            print(f"    ✅ API structure map saved to: {visualizations['structure_map']}")
            
            print("✅ All visualizations generated successfully!")
            
        except Exception as e:
            print(f"❌ Error generating visualizations: {e}")
            import traceback
            traceback.print_exc()
            # Return empty dict on error
            return {}
        
        return visualizations
    
    def create_visualization_report(self, endpoints: List[EndpointMetadata]) -> str:
        """
        Create a comprehensive visualization report.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Path to generated report
        """
        # Generate all visualizations
        visualizations = self.generate_all_visualizations(endpoints)
        
        if not visualizations:
            return ""
        
        # Create markdown report
        report_content = f"""# VAmPI API Visual Mapping Report

## Overview
This report contains visual representations of the VAmPI API structure discovered by the API Discovery Agent.

## Generated Visualizations

### 1. Endpoint Relationship Graph
![Endpoint Relationships]({visualizations['endpoint_graph']})

**Description:** Shows the hierarchical relationships between API endpoints, with nodes colored by risk level.

### 2. Security Risk Heatmap
![Security Risk Heatmap]({visualizations['risk_heatmap']})

**Description:** Displays the distribution of endpoints by risk level and HTTP methods.

### 3. Authentication Flow Diagram
![Authentication Flow]({visualizations['auth_flow']})

**Description:** Illustrates the authentication requirements and flow across different endpoint groups.

### 4. API Structure Map
![API Structure]({visualizations['structure_map']})

**Description:** Provides a comprehensive overview of the API structure organized by functionality.

## Summary
- **Total Endpoints Visualized:** {len(endpoints)}
- **Risk Levels Represented:** {len(set(ep.risk_level for ep in endpoints))}
- **Authentication Types:** {len(set(ep.authentication_type for ep in endpoints))}
- **HTTP Methods:** {len(set(method for ep in endpoints for method in ep.methods))}

## Files Generated
{chr(10).join(f"- {name}: {path}" for name, path in visualizations.items())}

---
*Generated by VAmPI API Discovery Agent Visual Mapping Module*
"""
        
        # Save the report
        output_path = self.output_dir / "visual_mapping_report.md"
        with open(output_path, 'w') as f:
            f.write(report_content)
        
        return str(output_path) 