#!/usr/bin/env python3
"""
HTML Security Assessment Report Generator
Generates a comprehensive HTML report from JSON security assessment data
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

class HTMLReportGenerator:
    def __init__(self, json_file_path: str):
        """Initialize the HTML report generator with JSON data"""
        self.json_file_path = json_file_path
        self.data = self._load_json_data()
        
    def _load_json_data(self) -> Dict[str, Any]:
        """Load JSON data from file"""
        try:
            with open(self.json_file_path, 'r', encoding='utf-8') as file:
                return json.load(file)
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            return {}
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    def _format_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return timestamp
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Info': '#17a2b8'
        }
        return colors.get(severity, '#6c757d')
    
    def _get_risk_level_color(self, risk_score: float) -> str:
        """Get color based on risk score"""
        if risk_score >= 8.0:
            return '#dc3545'  # Critical - Red
        elif risk_score >= 6.0:
            return '#fd7e14'  # High - Orange
        elif risk_score >= 4.0:
            return '#ffc107'  # Medium - Yellow
        elif risk_score >= 2.0:
            return '#28a745'  # Low - Green
        else:
            return '#17a2b8'  # Info - Blue
    
    def _generate_css(self) -> str:
        """Generate CSS styles for the report"""
        return """
        <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 5px solid;
        }
        
        .card.critical { border-left-color: #dc3545; }
        .card.high { border-left-color: #fd7e14; }
        .card.medium { border-left-color: #ffc107; }
        .card.low { border-left-color: #28a745; }
        .card.info { border-left-color: #17a2b8; }
        
        .card h3 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .card p {
            color: #666;
            font-size: 1.1em;
        }
        
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .section-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .section-header h2 {
            color: #495057;
            font-size: 1.5em;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .endpoint-card {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .endpoint-header {
            background: #f8f9fa;
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .endpoint-header:hover {
            background: #e9ecef;
        }
        
        .endpoint-path {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #495057;
        }
        
        .endpoint-methods {
            display: flex;
            gap: 5px;
        }
        
        .method-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        
        .method-get { background: #28a745; }
        .method-post { background: #007bff; }
        .method-put { background: #ffc107; color: #333; }
        .method-delete { background: #dc3545; }
        
        .risk-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            color: white;
        }
        
        .risk-critical { background: #dc3545; }
        .risk-high { background: #fd7e14; }
        .risk-medium { background: #ffc107; color: #333; }
        .risk-low { background: #28a745; }
        
        .vulnerability-item {
            border: 1px solid #dee2e6;
            border-radius: 6px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        
        .vulnerability-header {
            padding: 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .vulnerability-title {
            font-weight: bold;
            color: #495057;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; }
        .severity-info { background: #17a2b8; }
        
        .vulnerability-details {
            padding: 15px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            display: none;
        }
        
        .vulnerability-details.show {
            display: block;
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .detail-item {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #007bff;
        }
        
        .detail-item h4 {
            color: #495057;
            margin-bottom: 10px;
        }
        
        .detail-item p {
            color: #666;
            line-height: 1.5;
        }
        
        .code-block {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .recommendations {
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }
        
        .recommendations h4 {
            color: #0066cc;
            margin-bottom: 10px;
        }
        
        .recommendations ul {
            margin-left: 20px;
        }
        
        .recommendations li {
            margin-bottom: 5px;
            color: #333;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #dee2e6;
            margin-top: 50px;
        }
        
        .toggle-icon {
            transition: transform 0.3s ease;
        }
        
        .toggle-icon.rotated {
            transform: rotate(180deg);
        }
        
        .search-box {
            width: 100%;
            padding: 10px;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 1em;
        }
        
        .filter-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 1px solid #dee2e6;
            background: white;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .filter-btn:hover {
            background: #f8f9fa;
        }
        
        .filter-btn.active {
            background: #007bff;
            color: white;
            border-color: #007bff;
        }
        
        .hidden {
            display: none !important;
        }
        
        .vulnerability-item.hidden {
            display: none !important;
        }
        
        .filter-info {
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #1976d2;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
            
            .details-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """
    
    def _generate_javascript(self) -> str:
        """Generate JavaScript for interactive features"""
        return """
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Toggle vulnerability details
            document.querySelectorAll('.vulnerability-header').forEach(header => {
                header.addEventListener('click', function() {
                    const details = this.nextElementSibling;
                    const icon = this.querySelector('.toggle-icon');
                    
                    if (details.classList.contains('show')) {
                        details.classList.remove('show');
                        icon.classList.remove('rotated');
                    } else {
                        details.classList.add('show');
                        icon.classList.add('rotated');
                    }
                });
            });
            
            // Toggle endpoint details
            document.querySelectorAll('.endpoint-header').forEach(header => {
                header.addEventListener('click', function() {
                    const details = this.nextElementSibling;
                    const icon = this.querySelector('.toggle-icon');
                    
                    if (details.style.display === 'none' || details.style.display === '') {
                        details.style.display = 'block';
                        icon.classList.add('rotated');
                    } else {
                        details.style.display = 'none';
                        icon.classList.remove('rotated');
                    }
                });
            });
            
            // Search functionality - FIXED: Works with vulnerability filtering
            const searchBox = document.getElementById('searchBox');
            if (searchBox) {
                searchBox.addEventListener('input', function() {
                    const searchTerm = this.value.toLowerCase();
                    const endpoints = document.querySelectorAll('.endpoint-card');
                    
                    endpoints.forEach(endpoint => {
                        const text = endpoint.textContent.toLowerCase();
                        if (text.includes(searchTerm)) {
                            endpoint.classList.remove('hidden');
                            // Re-apply current filter after search
                            const activeFilter = document.querySelector('.filter-btn.active');
                            if (activeFilter && activeFilter.dataset.filter !== 'all') {
                                // Trigger the filter button click to recalculate statistics
                                activeFilter.click();
                            }
                        } else {
                            endpoint.classList.add('hidden');
                        }
                    });
                });
            }
            
            // Filter functionality - FIXED: Now filters vulnerabilities within endpoints
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    // Remove active class from all buttons
                    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                    // Add active class to clicked button
                    this.classList.add('active');
                    
                    const filter = this.dataset.filter;
                    const endpoints = document.querySelectorAll('.endpoint-card');
                    const filterInfo = document.getElementById('filterInfo');
                    const filterText = document.getElementById('filterText');
                    
                    // Update filter info display
                    if (filter === 'all') {
                        filterInfo.style.display = 'none';
                    } else {
                        filterInfo.style.display = 'block';
                        filterText.textContent = `Showing only ${filter.toUpperCase()} vulnerabilities`;
                    }
                    
                    endpoints.forEach(endpoint => {
                        const vulnerabilities = endpoint.querySelectorAll('.vulnerability-item');
                        let hasVisibleVulnerabilities = false;
                        
                        // Count visible vulnerabilities by severity
                        let visibleCritical = 0;
                        let visibleHigh = 0;
                        let visibleMedium = 0;
                        let visibleLow = 0;
                        
                        vulnerabilities.forEach(vuln => {
                            const severityBadge = vuln.querySelector('.severity-badge');
                            if (severityBadge) {
                                const severity = severityBadge.textContent.toLowerCase();
                                
                                if (filter === 'all') {
                                    vuln.classList.remove('hidden');
                                    hasVisibleVulnerabilities = true;
                                    // Count all visible vulnerabilities
                                    if (severity === 'critical') visibleCritical++;
                                    else if (severity === 'high') visibleHigh++;
                                    else if (severity === 'medium') visibleMedium++;
                                    else if (severity === 'low') visibleLow++;
                                } else if (severity === filter) {
                                    vuln.classList.remove('hidden');
                                    hasVisibleVulnerabilities = true;
                                    // Count only the filtered severity - FIXED: Only count the specific severity being filtered
                                    if (severity === filter) {
                                        if (severity === 'critical') visibleCritical++;
                                        else if (severity === 'high') visibleHigh++;
                                        else if (severity === 'medium') visibleMedium++;
                                        else if (severity === 'low') visibleLow++;
                                    }
                                } else {
                                    vuln.classList.add('hidden');
                                    // Don't count hidden vulnerabilities
                                }
                            }
                        });
                        
                        // Update endpoint statistics based on visible vulnerabilities
                        const totalVisible = visibleCritical + visibleHigh + visibleMedium + visibleLow;
                        const statCritical = endpoint.querySelector('.stat-critical');
                        const statHigh = endpoint.querySelector('.stat-high');
                        const statMedium = endpoint.querySelector('.stat-medium');
                        const statLow = endpoint.querySelector('.stat-low');
                        const statRisk = endpoint.querySelector('.stat-risk');
                        
                        if (statCritical) statCritical.textContent = visibleCritical;
                        if (statHigh) statHigh.textContent = visibleHigh;
                        if (statMedium) statMedium.textContent = visibleMedium;
                        if (statLow) statLow.textContent = visibleLow;
                        
                        // Calculate risk score based on visible vulnerabilities
                        if (statRisk && totalVisible > 0) {
                            let riskScore;
                            if (filter === 'all') {
                                // For 'all' filter, use weighted average
                                riskScore = (visibleCritical * 10.0 + visibleHigh * 7.0 + visibleMedium * 4.0 + visibleLow * 1.0) / totalVisible;
                            } else {
                                // For specific severity filters, use the severity's base risk score
                                if (filter === 'critical') riskScore = 10.0;
                                else if (filter === 'high') riskScore = 7.0;
                                else if (filter === 'medium') riskScore = 4.0;
                                else if (filter === 'low') riskScore = 1.0;
                                else riskScore = 0.0;
                            }
                            statRisk.textContent = riskScore.toFixed(2);
                        } else if (statRisk) {
                            statRisk.textContent = '0.00';
                        }
                        
                        // Update endpoint header vulnerability count
                        const endpointVulnCount = endpoint.querySelector('.endpoint-header span[style*="font-size: 0.9em"]');
                        if (endpointVulnCount) {
                            endpointVulnCount.textContent = `${totalVisible} vulnerabilities`;
                        }
                        
                        // Update risk badge based on filtered severity
                        const riskBadge = endpoint.querySelector('.risk-badge');
                        if (riskBadge && totalVisible > 0) {
                            let newRiskLevel;
                            if (filter === 'all') {
                                // For 'all' filter, use highest visible severity
                                if (visibleCritical > 0) newRiskLevel = 'critical';
                                else if (visibleHigh > 0) newRiskLevel = 'high';
                                else if (visibleMedium > 0) newRiskLevel = 'medium';
                                else if (visibleLow > 0) newRiskLevel = 'low';
                                else newRiskLevel = 'low';
                            } else {
                                // For specific severity filters, use the filter severity
                                newRiskLevel = filter;
                            }
                            
                            // Remove old risk class and add new one
                            riskBadge.className = `risk-badge risk-${newRiskLevel}`;
                            riskBadge.textContent = newRiskLevel.toUpperCase();
                        }
                        
                        // Show/hide endpoint based on whether it has visible vulnerabilities
                        if (filter === 'all' || hasVisibleVulnerabilities) {
                            endpoint.classList.remove('hidden');
                        } else {
                            endpoint.classList.add('hidden');
                        }
                    });
                });
            });
        });
        </script>
        """
    
    def _generate_header(self) -> str:
        """Generate report header"""
        data = self.data
        return f"""
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <div class="subtitle">
                <strong>Target:</strong> {self._escape_html(data.get('target_application', 'Unknown'))} | 
                <strong>Assessment Date:</strong> {self._format_timestamp(data.get('assessment_start_time', ''))} |
                <strong>Report ID:</strong> {self._escape_html(data.get('report_id', 'N/A'))}
            </div>
        </div>
        """
    
    def _generate_summary_cards(self) -> str:
        """Generate summary cards"""
        data = self.data
        return f"""
        <div class="summary-cards">
            <div class="card critical">
                <h3>{data.get('critical_vulnerabilities', 0)}</h3>
                <p>Critical Vulnerabilities</p>
            </div>
            <div class="card high">
                <h3>{data.get('high_vulnerabilities', 0)}</h3>
                <p>High Vulnerabilities</p>
            </div>
            <div class="card medium">
                <h3>{data.get('medium_vulnerabilities', 0)}</h3>
                <p>Medium Vulnerabilities</p>
            </div>
            <div class="card low">
                <h3>{data.get('low_vulnerabilities', 0)}</h3>
                <p>Low Vulnerabilities</p>
            </div>
            <div class="card info">
                <h3>{data.get('total_endpoints_tested', 0)}</h3>
                <p>Endpoints Tested</p>
            </div>
        </div>
        """
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary section"""
        data = self.data
        summary = data.get('executive_summary', '')
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>📊 Executive Summary</h2>
            </div>
            <div class="section-content">
                <div style="white-space: pre-line; line-height: 1.8; font-size: 1.1em;">
                    {self._escape_html(summary)}
                </div>
            </div>
        </div>
        """
    
    def _generate_vulnerability_details(self, vulnerability: Dict[str, Any]) -> str:
        """Generate detailed vulnerability information"""
        details = vulnerability.get('vulnerability_details', '')
        cvss = vulnerability.get('cvss_metrics', {})
        recommendations = vulnerability.get('recommendations', [])
        poc = vulnerability.get('proof_of_concept', '')
        
        details_html = f"""
        <div class="details-grid">
            <div class="detail-item">
                <h4>📋 Description</h4>
                <div style="white-space: pre-line;">{self._escape_html(details)}</div>
            </div>
        """
        
        if cvss:
            details_html += f"""
            <div class="detail-item">
                <h4>🎯 CVSS Metrics</h4>
                <p><strong>Base Score:</strong> {cvss.get('base_score', 'N/A')}</p>
                <p><strong>Severity:</strong> {cvss.get('base_severity', 'N/A')}</p>
                <p><strong>Attack Vector:</strong> {cvss.get('attack_vector', 'N/A')}</p>
                <p><strong>Attack Complexity:</strong> {cvss.get('attack_complexity', 'N/A')}</p>
                <p><strong>Privileges Required:</strong> {cvss.get('privileges_required', 'N/A')}</p>
            </div>
            """
        
        if poc:
            details_html += f"""
            <div class="detail-item">
                <h4>💻 Proof of Concept</h4>
                <div class="code-block">{self._escape_html(poc)}</div>
            </div>
            """
        
        details_html += "</div>"
        
        if recommendations:
            details_html += f"""
            <div class="recommendations">
                <h4>🔧 Recommendations</h4>
                <ul>
                    {''.join([f'<li>{self._escape_html(rec)}</li>' for rec in recommendations])}
                </ul>
            </div>
            """
        
        return details_html
    
    def _generate_endpoint_section(self) -> str:
        """Generate endpoint vulnerabilities section"""
        data = self.data
        endpoints = data.get('endpoint_reports', [])
        
        html = f"""
        <div class="section">
            <div class="section-header">
                <h2>🎯 Endpoint Vulnerabilities</h2>
            </div>
            <div class="section-content">
                <input type="text" id="searchBox" class="search-box" placeholder="Search endpoints...">
                <div class="filter-buttons">
                    <button class="filter-btn active" data-filter="all">All</button>
                    <button class="filter-btn" data-filter="critical">Critical</button>
                    <button class="filter-btn" data-filter="high">High</button>
                    <button class="filter-btn" data-filter="medium">Medium</button>
                    <button class="filter-btn" data-filter="low">Low</button>
                </div>
                <div id="filterInfo" class="filter-info" style="display: none;">
                    <strong>Filter Active:</strong> <span id="filterText">All vulnerabilities</span>
                </div>
        """
        
        for endpoint in endpoints:
            endpoint_path = endpoint.get('endpoint_path', 'Unknown')
            methods = endpoint.get('http_methods', [])
            vulnerabilities = endpoint.get('vulnerabilities_found', 0)
            critical = endpoint.get('critical_vulnerabilities', 0)
            high = endpoint.get('high_vulnerabilities', 0)
            medium = endpoint.get('medium_vulnerabilities', 0)
            low = endpoint.get('low_vulnerabilities', 0)
            risk_score = endpoint.get('overall_risk_score', 0)
            
            # Determine risk level
            if critical > 0:
                risk_level = 'critical'
            elif high > 0:
                risk_level = 'high'
            elif medium > 0:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            html += f"""
            <div class="endpoint-card">
                <div class="endpoint-header">
                    <div>
                        <div class="endpoint-path">{self._escape_html(endpoint_path)}</div>
                        <div class="endpoint-methods">
                            {''.join([f'<span class="method-badge method-{method.lower()}">{method}</span>' for method in methods])}
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span class="risk-badge risk-{risk_level}">{risk_level.upper()}</span>
                        <span style="font-size: 0.9em; color: #666;">{vulnerabilities} vulnerabilities</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                </div>
                <div class="endpoint-details" style="display: none; padding: 20px; background: #f8f9fa;">
                    <div class="endpoint-stats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                        <div><strong>Critical:</strong> <span class="stat-critical">{critical}</span></div>
                        <div><strong>High:</strong> <span class="stat-high">{high}</span></div>
                        <div><strong>Medium:</strong> <span class="stat-medium">{medium}</span></div>
                        <div><strong>Low:</strong> <span class="stat-low">{low}</span></div>
                        <div><strong>Risk Score:</strong> <span class="stat-risk">{risk_score:.2f}</span></div>
                    </div>
            """
            
            # Add vulnerabilities
            security_tests = endpoint.get('security_tests', [])
            vulnerabilities_found = [test for test in security_tests if test.get('vulnerability_found', False)]
            
            if vulnerabilities_found:
                html += "<h4 style='margin-bottom: 15px; color: #495057;'>🔍 Vulnerabilities Found:</h4>"
                
                for vuln in vulnerabilities_found:
                    test_name = vuln.get('test_name', 'Unknown Test')
                    severity = vuln.get('severity', 'Info')
                    test_category = vuln.get('test_category', 'Unknown')
                    
                    html += f"""
                    <div class="vulnerability-item">
                        <div class="vulnerability-header">
                            <div class="vulnerability-title">
                                {self._escape_html(test_name)} - {self._escape_html(test_category)}
                            </div>
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <span class="severity-badge severity-{severity.lower()}">{severity}</span>
                                <span class="toggle-icon">▼</span>
                            </div>
                        </div>
                        <div class="vulnerability-details">
                            {self._generate_vulnerability_details(vuln)}
                        </div>
                    </div>
                    """
            
            html += """
                </div>
            </div>
            """
        
        html += """
            </div>
        </div>
        """
        
        return html
    
    def _generate_footer(self) -> str:
        """Generate report footer"""
        return f"""
        <div class="footer">
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | VAmPI Security Assessment Report</p>
            <p>This report contains sensitive security information and should be handled with appropriate confidentiality.</p>
        </div>
        """
    
    def generate_html_report(self, output_file: str = None) -> str:
        """Generate complete HTML report"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"security_assessment_report_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {self._escape_html(self.data.get('target_application', 'Unknown'))}</title>
            {self._generate_css()}
        </head>
        <body>
            <div class="container">
                {self._generate_header()}
                {self._generate_summary_cards()}
                {self._generate_executive_summary()}
                {self._generate_endpoint_section()}
                {self._generate_footer()}
            </div>
            {self._generate_javascript()}
        </body>
        </html>
        """
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file

def main():
    """Main function to generate HTML report"""
    json_file = "security_assessment_report.json"
    
    if not os.path.exists(json_file):
        print(f"Error: JSON file '{json_file}' not found!")
        return
    
    try:
        generator = HTMLReportGenerator(json_file)
        output_file = generator.generate_html_report()
        print(f"✅ HTML report generated successfully: {output_file}")
        print(f"📊 Report contains {generator.data.get('total_vulnerabilities', 0)} vulnerabilities across {generator.data.get('total_endpoints_tested', 0)} endpoints")
    except Exception as e:
        print(f"❌ Error generating HTML report: {e}")

if __name__ == "__main__":
    main()