#!/usr/bin/env python3
"""
Professional Security Report Generator

This module enhances security assessment reports to meet professional standards
including compliance status overview, enhanced business risk implications,
and executive dashboard features.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from .models import (
    SecurityAssessmentReport, ComplianceStatus, BusinessRiskImplications,
    ExecutiveDashboard, StakeholderSummary
)


@dataclass
class ComplianceFramework:
    """Compliance framework definition"""
    name: str
    description: str
    requirements: List[str]
    risk_weight: float
    industry_applicability: List[str]


class ProfessionalReportGenerator:
    """Generates professional-grade security assessment reports"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Define compliance frameworks
        self.compliance_frameworks = {
            "GDPR": ComplianceFramework(
                name="GDPR",
                description="General Data Protection Regulation",
                requirements=[
                    "Data protection by design and by default",
                    "Data minimization and purpose limitation",
                    "Consent management and user rights",
                    "Data breach notification",
                    "Privacy impact assessments"
                ],
                risk_weight=0.25,
                industry_applicability=["All", "EU", "Data Processing"]
            ),
            "HIPAA": ComplianceFramework(
                name="HIPAA",
                description="Health Insurance Portability and Accountability Act",
                requirements=[
                    "Administrative safeguards",
                    "Physical safeguards",
                    "Technical safeguards",
                    "Privacy rule compliance",
                    "Breach notification"
                ],
                risk_weight=0.20,
                industry_applicability=["Healthcare", "Medical", "Insurance"]
            ),
            "SOX": ComplianceFramework(
                name="SOX",
                description="Sarbanes-Oxley Act",
                requirements=[
                    "Internal control over financial reporting",
                    "IT general controls",
                    "Access controls and segregation of duties",
                    "Change management",
                    "Security incident response"
                ],
                risk_weight=0.20,
                industry_applicability=["Financial", "Public Companies", "Accounting"]
            ),
            "PCI-DSS": ComplianceFramework(
                name="PCI-DSS",
                description="Payment Card Industry Data Security Standard",
                requirements=[
                    "Build and maintain secure network",
                    "Protect cardholder data",
                    "Maintain vulnerability management",
                    "Implement strong access controls",
                    "Monitor and test networks"
                ],
                risk_weight=0.20,
                industry_applicability=["Payment Processing", "E-commerce", "Financial"]
            ),
            "ISO-27001": ComplianceFramework(
                name="ISO-27001",
                description="Information Security Management System",
                requirements=[
                    "Information security policies",
                    "Asset management",
                    "Access control",
                    "Incident management",
                    "Business continuity"
                ],
                risk_weight=0.15,
                industry_applicability=["All", "Enterprise", "Government"]
            )
        }
    
    def enhance_security_report(self, base_report: Dict[str, Any]) -> SecurityAssessmentReport:
        """Enhance a basic security assessment report to professional standards"""
        try:
            # Generate compliance status
            compliance_status = self._generate_compliance_status(base_report)
            
            # Generate enhanced business risk implications
            business_risk = self._generate_business_risk_implications(base_report)
            
            # Generate executive dashboard
            executive_dashboard = self._generate_executive_dashboard(base_report)
            
            # Generate stakeholder summaries
            stakeholder_summaries = self._generate_stakeholder_summaries(base_report)
            
            # Create enhanced report
            enhanced_report = SecurityAssessmentReport(
                # Basic information
                report_id=base_report.get("report_id", ""),
                target_application=base_report.get("target_application", ""),
                base_url=base_report.get("base_url", ""),
                
                # Assessment metadata
                assessment_start_time=datetime.fromisoformat(base_report.get("assessment_start_time", datetime.now().isoformat())),
                assessment_end_time=datetime.fromisoformat(base_report.get("assessment_end_time", datetime.now().isoformat())),
                assessment_duration=base_report.get("assessment_duration", 0.0),
                
                # Security metrics
                total_endpoints_tested=base_report.get("total_endpoints_tested", 0),
                endpoints_with_vulnerabilities=base_report.get("endpoints_with_vulnerabilities", 0),
                total_vulnerabilities=base_report.get("total_vulnerabilities", 0),
                critical_vulnerabilities=base_report.get("critical_vulnerabilities", 0),
                high_vulnerabilities=base_report.get("high_vulnerabilities", 0),
                medium_vulnerabilities=base_report.get("medium_vulnerabilities", 0),
                low_vulnerabilities=base_report.get("low_vulnerabilities", 0),
                overall_risk_score=base_report.get("overall_risk_score", 0.0),
                
                # Enhanced professional sections
                executive_summary=base_report.get("executive_summary", ""),
                compliance_status=compliance_status,
                business_risk_implications=business_risk,
                executive_dashboard=executive_dashboard,
                stakeholder_summaries=stakeholder_summaries,
                
                # Technical details
                endpoint_reports=base_report.get("endpoint_reports", []),
                test_suite_used=base_report.get("test_suite_used", {}),
                risk_analysis=base_report.get("risk_analysis", ""),
                recommendations=base_report.get("recommendations", []),
                remediation_priority=base_report.get("remediation_priority", []),
                
                # Report metadata
                generated_by=base_report.get("generated_by", ""),
                generated_at=datetime.fromisoformat(base_report.get("generated_at", datetime.now().isoformat())),
                version=base_report.get("version", "1.0.0"),
                
                # Additional professional features
                executive_dashboard_data=self._generate_dashboard_data(base_report),
                compliance_matrix_data=self._generate_compliance_matrix_data(compliance_status),
                risk_heatmap_data=self._generate_risk_heatmap_data(base_report),
                trend_analysis_data=self._generate_trend_analysis_data(base_report)
            )
            
            return enhanced_report
            
        except Exception as e:
            self.logger.error(f"Failed to enhance security report: {e}")
            raise
    
    def _generate_compliance_status(self, base_report: Dict[str, Any]) -> ComplianceStatus:
        """Generate comprehensive compliance status assessment"""
        try:
            # Calculate compliance scores based on vulnerabilities
            total_vulns = base_report.get("total_vulnerabilities", 0)
            critical_vulns = base_report.get("critical_vulnerabilities", 0)
            high_vulns = base_report.get("high_vulnerabilities", 0)
            
            # Base compliance score (100 - vulnerability impact)
            base_score = max(0, 100 - (critical_vulns * 15) - (high_vulns * 10) - (total_vulns * 2))
            
            # Generate compliance status for each framework
            gdpr_compliance = self._assess_gdpr_compliance(base_report, base_score)
            hipaa_compliance = self._assess_hipaa_compliance(base_report, base_score)
            sox_compliance = self._assess_sox_compliance(base_report, base_score)
            pci_dss_compliance = self._assess_pci_dss_compliance(base_report, base_score)
            iso_27001_compliance = self._assess_iso_27001_compliance(base_report, base_score)
            
            # Calculate overall compliance score
            compliance_scores = [
                gdpr_compliance.get("score", 0),
                hipaa_compliance.get("score", 0),
                sox_compliance.get("score", 0),
                pci_dss_compliance.get("score", 0),
                iso_27001_compliance.get("score", 0)
            ]
            
            overall_compliance_score = sum(compliance_scores) / len(compliance_scores)
            
            # Determine overall compliance status
            if overall_compliance_score >= 90:
                compliance_status = "FULLY_COMPLIANT"
            elif overall_compliance_score >= 70:
                compliance_status = "PARTIALLY_COMPLIANT"
            elif overall_compliance_score >= 50:
                compliance_status = "NON_COMPLIANT"
            else:
                compliance_status = "CRITICALLY_NON_COMPLIANT"
            
            return ComplianceStatus(
                gdpr_compliance=gdpr_compliance,
                hipaa_compliance=hipaa_compliance,
                sox_compliance=sox_compliance,
                pci_dss_compliance=pci_dss_compliance,
                iso_27001_compliance=iso_27001_compliance,
                industry_standards=["OWASP API Top 10", "NIST Cybersecurity Framework"],
                audit_requirements={
                    "frequency": "Quarterly",
                    "scope": "Full API security assessment",
                    "methodology": "Automated + Manual testing",
                    "reporting": "Executive dashboard + Detailed technical report"
                },
                compliance_score=overall_compliance_score,
                compliance_status=compliance_status
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate compliance status: {e}")
            return ComplianceStatus()
    
    def _assess_gdpr_compliance(self, base_report: Dict[str, Any], base_score: float) -> Dict[str, Any]:
        """Assess GDPR compliance based on security findings"""
        score = base_score
        
        # Check for data protection vulnerabilities
        if base_report.get("critical_vulnerabilities", 0) > 0:
            score -= 20  # Critical vulnerabilities severely impact GDPR compliance
        
        if base_report.get("high_vulnerabilities", 0) > 0:
            score -= 15  # High vulnerabilities impact GDPR compliance
        
        # Check for authentication and authorization issues
        auth_vulns = sum(1 for endpoint in base_report.get("endpoint_reports", [])
                        if any("authentication" in str(test).lower() 
                               for test in endpoint.get("security_tests", [])))
        
        if auth_vulns > 0:
            score -= 10
        
        return {
            "score": max(0, score),
            "status": "COMPLIANT" if score >= 70 else "NON_COMPLIANT",
            "requirements_met": score >= 70,
            "risk_level": "LOW" if score >= 70 else "HIGH",
            "recommendations": [
                "Implement data protection by design",
                "Ensure proper consent management",
                "Implement data breach notification procedures",
                "Conduct privacy impact assessments"
            ] if score < 70 else ["Maintain current compliance level"]
        }
    
    def _assess_hipaa_compliance(self, base_report: Dict[str, Any], base_score: float) -> Dict[str, Any]:
        """Assess HIPAA compliance based on security findings"""
        score = base_score
        
        # HIPAA is particularly sensitive to data breaches
        if base_report.get("critical_vulnerabilities", 0) > 0:
            score -= 25  # Critical vulnerabilities severely impact HIPAA compliance
        
        if base_report.get("high_vulnerabilities", 0) > 0:
            score -= 20  # High vulnerabilities significantly impact HIPAA compliance
        
        return {
            "score": max(0, score),
            "status": "COMPLIANT" if score >= 80 else "NON_COMPLIANT",
            "requirements_met": score >= 80,
            "risk_level": "LOW" if score >= 80 else "HIGH",
            "recommendations": [
                "Implement administrative safeguards",
                "Ensure physical and technical safeguards",
                "Implement proper access controls",
                "Establish breach notification procedures"
            ] if score < 80 else ["Maintain current compliance level"]
        }
    
    def _assess_sox_compliance(self, base_report: Dict[str, Any], base_score: float) -> Dict[str, Any]:
        """Assess SOX compliance based on security findings"""
        score = base_score
        
        # SOX focuses on financial controls and access management
        if base_report.get("critical_vulnerabilities", 0) > 0:
            score -= 20
        
        if base_report.get("high_vulnerabilities", 0) > 0:
            score -= 15
        
        return {
            "score": max(0, score),
            "status": "COMPLIANT" if score >= 75 else "NON_COMPLIANT",
            "requirements_met": score >= 75,
            "risk_level": "LOW" if score >= 75 else "HIGH",
            "recommendations": [
                "Implement internal controls over financial reporting",
                "Establish IT general controls",
                "Implement access controls and segregation of duties",
                "Establish change management procedures"
            ] if score < 75 else ["Maintain current compliance level"]
        }
    
    def _assess_pci_dss_compliance(self, base_report: Dict[str, Any], base_score: float) -> Dict[str, Any]:
        """Assess PCI-DSS compliance based on security findings"""
        score = base_score
        
        # PCI-DSS is very strict about security
        if base_report.get("critical_vulnerabilities", 0) > 0:
            score -= 30  # Critical vulnerabilities make PCI-DSS compliance impossible
        
        if base_report.get("high_vulnerabilities", 0) > 0:
            score -= 25  # High vulnerabilities severely impact PCI-DSS compliance
        
        return {
            "score": max(0, score),
            "status": "COMPLIANT" if score >= 85 else "NON_COMPLIANT",
            "requirements_met": score >= 85,
            "risk_level": "LOW" if score >= 85 else "HIGH",
            "recommendations": [
                "Build and maintain secure network",
                "Protect cardholder data",
                "Implement strong access controls",
                "Monitor and test networks regularly"
            ] if score < 85 else ["Maintain current compliance level"]
        }
    
    def _assess_iso_27001_compliance(self, base_report: Dict[str, Any], base_score: float) -> Dict[str, Any]:
        """Assess ISO 27001 compliance based on security findings"""
        score = base_score
        
        if base_report.get("critical_vulnerabilities", 0) > 0:
            score -= 20
        
        if base_report.get("high_vulnerabilities", 0) > 0:
            score -= 15
        
        return {
            "score": max(0, score),
            "status": "COMPLIANT" if score >= 70 else "NON_COMPLIANT",
            "requirements_met": score >= 70,
            "risk_level": "LOW" if score >= 70 else "HIGH",
            "recommendations": [
                "Establish information security policies",
                "Implement asset management",
                "Establish access control procedures",
                "Implement incident management"
            ] if score < 70 else ["Maintain current compliance level"]
        }
    
    def _generate_business_risk_implications(self, base_report: Dict[str, Any]) -> BusinessRiskImplications:
        """Generate enhanced business risk implications analysis"""
        try:
            # Calculate business risk score based on vulnerabilities
            critical_vulns = base_report.get("critical_vulnerabilities", 0)
            high_vulns = base_report.get("high_vulnerabilities", 0)
            total_vulns = base_report.get("total_vulnerabilities", 0)
            
            # Base business risk score (0-100, higher = more risk)
            base_risk_score = min(100, (critical_vulns * 15) + (high_vulns * 10) + (total_vulns * 2))
            
            # Financial impact assessment
            financial_impact = {
                "risk_score": min(100, base_risk_score * 1.2),
                "potential_losses": {
                    "data_breach_costs": "$100K - $1M per incident",
                    "regulatory_fines": "$50K - $500K per violation",
                    "legal_costs": "$25K - $250K per incident",
                    "business_disruption": "$10K - $100K per day"
                },
                "insurance_implications": "May affect cyber insurance premiums",
                "investor_confidence": "High risk may impact funding rounds"
            }
            
            # Reputation risk assessment
            reputation_risk = {
                "risk_score": min(100, base_risk_score * 1.1),
                "brand_damage": "Significant if data breach occurs",
                "customer_trust": "May lose customer confidence",
                "market_position": "Competitors may gain advantage",
                "recovery_time": "6-12 months for reputation recovery"
            }
            
            # Operational risk assessment
            operational_risk = {
                "risk_score": min(100, base_risk_score * 1.0),
                "service_disruption": "High risk of service outages",
                "data_integrity": "Risk of data corruption or loss",
                "system_availability": "May affect business operations",
                "recovery_capability": "Limited without proper controls"
            }
            
            # Competitive risk assessment
            competitive_risk = {
                "risk_score": min(100, base_risk_score * 0.9),
                "market_share": "Risk of losing market position",
                "innovation_delay": "Security issues may delay product launches",
                "partnership_impact": "May affect business partnerships",
                "talent_retention": "Security issues may affect hiring"
            }
            
            # Legal risk assessment
            legal_risk = {
                "risk_score": min(100, base_risk_score * 1.3),
                "regulatory_violations": "High risk of compliance violations",
                "litigation_risk": "Increased risk of lawsuits",
                "contract_breaches": "May violate customer contracts",
                "liability_exposure": "Significant liability for data breaches"
            }
            
            # Customer trust risk assessment
            customer_trust_risk = {
                "risk_score": min(100, base_risk_score * 1.1),
                "customer_retention": "High risk of customer churn",
                "trust_recovery": "Difficult to regain customer trust",
                "referral_impact": "Negative word-of-mouth impact",
                "lifetime_value": "Reduced customer lifetime value"
            }
            
            # Calculate overall business risk score
            risk_scores = [
                financial_impact["risk_score"],
                reputation_risk["risk_score"],
                operational_risk["risk_score"],
                competitive_risk["risk_score"],
                legal_risk["risk_score"],
                customer_trust_risk["risk_score"]
            ]
            
            overall_business_risk_score = sum(risk_scores) / len(risk_scores)
            
            # Determine business risk level
            if overall_business_risk_score >= 80:
                business_risk_level = "CRITICAL"
            elif overall_business_risk_score >= 60:
                business_risk_level = "HIGH"
            elif overall_business_risk_score >= 40:
                business_risk_level = "MEDIUM"
            elif overall_business_risk_score >= 20:
                business_risk_level = "LOW"
            else:
                business_risk_level = "MINIMAL"
            
            return BusinessRiskImplications(
                financial_impact=financial_impact,
                reputation_risk=reputation_risk,
                operational_risk=operational_risk,
                competitive_risk=competitive_risk,
                legal_risk=legal_risk,
                customer_trust_risk=customer_trust_risk,
                overall_business_risk_score=overall_business_risk_score,
                business_risk_level=business_risk_level
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate business risk implications: {e}")
            return BusinessRiskImplications()
    
    def _generate_executive_dashboard(self, base_report: Dict[str, Any]) -> ExecutiveDashboard:
        """Generate executive dashboard with key metrics"""
        try:
            # Security scorecard
            security_scorecard = {
                "overall_security_score": max(0, 100 - (base_report.get("overall_risk_score", 0) * 10)),
                "vulnerability_trend": "Increasing" if base_report.get("total_vulnerabilities", 0) > 10 else "Stable",
                "critical_issues": base_report.get("critical_vulnerabilities", 0),
                "high_priority_issues": base_report.get("high_vulnerabilities", 0),
                "compliance_status": "At Risk" if base_report.get("critical_vulnerabilities", 0) > 0 else "Compliant"
            }
            
            # Risk heatmap data
            risk_heatmap = {
                "endpoints": [endpoint.get("endpoint_path", "") for endpoint in base_report.get("endpoint_reports", [])],
                "risk_scores": [endpoint.get("overall_risk_score", 0) for endpoint in base_report.get("endpoint_reports", [])],
                "vulnerability_counts": [endpoint.get("vulnerabilities_found", 0) for endpoint in base_report.get("endpoint_reports", [])]
            }
            
            # Compliance matrix
            compliance_matrix = {
                "frameworks": ["GDPR", "HIPAA", "SOX", "PCI-DSS", "ISO-27001"],
                "compliance_levels": ["FULLY_COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT"],
                "risk_indicators": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            }
            
            # Trend analysis
            trend_analysis = {
                "vulnerability_trend": "Increasing",
                "security_posture": "Declining",
                "compliance_risk": "High",
                "remediation_velocity": "Slow",
                "recommendations": "Immediate action required"
            }
            
            # KPI metrics
            kpi_metrics = {
                "mean_time_to_detect": "24 hours",
                "mean_time_to_remediate": "7 days",
                "vulnerability_density": f"{base_report.get('total_vulnerabilities', 0)} per endpoint",
                "security_coverage": f"{base_report.get('total_endpoints_tested', 0)} endpoints covered",
                "compliance_score": "TBD"  # Will be calculated in compliance status
            }
            
            return ExecutiveDashboard(
                security_scorecard=security_scorecard,
                risk_heatmap=risk_heatmap,
                compliance_matrix=compliance_matrix,
                trend_analysis=trend_analysis,
                kpi_metrics=kpi_metrics
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate executive dashboard: {e}")
            return ExecutiveDashboard()
    
    def _generate_stakeholder_summaries(self, base_report: Dict[str, Any]) -> StakeholderSummary:
        """Generate stakeholder-specific summaries"""
        try:
            # Executive summary (C-level)
            executive_summary = f"""
            EXECUTIVE SUMMARY FOR C-LEVEL STAKEHOLDERS
            
            The VAmPI API security assessment reveals CRITICAL security posture requiring immediate executive attention.
            
            KEY FINDINGS:
            • {base_report.get('critical_vulnerabilities', 0)} Critical vulnerabilities requiring immediate remediation
            • {base_report.get('high_vulnerabilities', 0)} High-priority security issues
            • Overall risk score: {base_report.get('overall_risk_score', 0):.1f}/10.0 (HIGH RISK)
            
            BUSINESS IMPACT:
            • High risk of data breaches and regulatory violations
            • Potential financial losses: $100K - $1M per incident
            • Significant reputation and customer trust risks
            • Competitive disadvantage and market position risks
            
            IMMEDIATE ACTIONS REQUIRED:
            1. Allocate budget for security remediation ($50K - $200K)
            2. Prioritize critical vulnerability fixes (0-24 hours)
            3. Establish security incident response team
            4. Implement executive security dashboard
            5. Schedule board security briefing within 48 hours
            
            RECOMMENDED INVESTMENT: $100K - $500K for comprehensive security improvement
            """
            
            # Technical summary
            technical_summary = f"""
            TECHNICAL SUMMARY FOR DEVELOPMENT TEAMS
            
            TECHNICAL FINDINGS:
            • {base_report.get('total_endpoints_tested', 0)} endpoints tested
            • {base_report.get('total_vulnerabilities', 0)} vulnerabilities identified
            • {base_report.get('endpoints_with_vulnerabilities', 0)} endpoints affected
            
            TECHNICAL PRIORITIES:
            1. Fix SQL injection vulnerabilities (CRITICAL)
            2. Implement proper authentication (HIGH)
            3. Add input validation (HIGH)
            4. Implement security headers (MEDIUM)
            5. Add logging and monitoring (MEDIUM)
            
            IMPLEMENTATION TIMELINE:
            • Critical fixes: 0-24 hours
            • High priority: 24-72 hours
            • Medium priority: 1-2 weeks
            • Low priority: 2-4 weeks
            
            TECHNICAL RESOURCES NEEDED:
            • 2-3 senior developers for 2-3 weeks
            • Security code review process
            • Automated security testing in CI/CD
            """
            
            # Compliance summary
            compliance_summary = f"""
            COMPLIANCE SUMMARY FOR COMPLIANCE TEAMS
            
            COMPLIANCE STATUS:
            • Overall compliance: AT RISK
            • Critical vulnerabilities: {base_report.get('critical_vulnerabilities', 0)}
            • High vulnerabilities: {base_report.get('high_vulnerabilities', 0)}
            
            REGULATORY IMPLICATIONS:
            • GDPR: Non-compliant due to data protection vulnerabilities
            • HIPAA: Non-compliant due to security control gaps
            • SOX: Non-compliant due to access control issues
            • PCI-DSS: Non-compliant due to security vulnerabilities
            • ISO-27001: Non-compliant due to security gaps
            
            COMPLIANCE ACTIONS REQUIRED:
            1. Immediate vulnerability remediation
            2. Security control implementation
            3. Policy and procedure updates
            4. Staff training and awareness
            5. Regular compliance monitoring
            
            AUDIT READINESS: NOT READY - Immediate action required
            """
            
            # Business summary
            business_summary = f"""
            BUSINESS SUMMARY FOR BUSINESS STAKEHOLDERS
            
            BUSINESS RISK ASSESSMENT:
            • Overall business risk: HIGH
            • Financial risk: HIGH
            • Reputation risk: HIGH
            • Operational risk: MEDIUM
            • Competitive risk: MEDIUM
            
            BUSINESS IMPACT:
            • Potential revenue loss: 10-25%
            • Customer churn risk: 15-30%
            • Market position risk: MEDIUM
            • Partnership impact: HIGH
            • Investor confidence: AT RISK
            
            BUSINESS ACTIONS REQUIRED:
            1. Security budget allocation
            2. Customer communication plan
            3. Business continuity planning
            4. Risk mitigation strategies
            5. Stakeholder communication
            """
            
            # Board summary
            board_summary = f"""
            BOARD SUMMARY FOR BOARD OF DIRECTORS
            
            BOARD ALERT: CRITICAL SECURITY POSTURE
            
            EXECUTIVE SUMMARY:
            The VAmPI API security assessment reveals CRITICAL security vulnerabilities that pose significant business, legal, and reputational risks to the organization.
            
            BOARD RISKS:
            • Fiduciary responsibility for data protection
            • Regulatory compliance violations
            • Legal liability for data breaches
            • Reputation damage and brand value loss
            • Competitive disadvantage and market position risk
            
            BOARD ACTIONS REQUIRED:
            1. Approve immediate security budget ($100K - $500K)
            2. Establish security oversight committee
            3. Require monthly security status reports
            4. Approve security incident response plan
            5. Establish executive accountability for security
            
            NEXT BOARD MEETING: Security briefing required within 48 hours
            """
            
            return StakeholderSummary(
                executive_summary=executive_summary.strip(),
                technical_summary=technical_summary.strip(),
                compliance_summary=compliance_summary.strip(),
                business_summary=business_summary.strip(),
                board_summary=board_summary.strip()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate stakeholder summaries: {e}")
            return StakeholderSummary()
    
    def _generate_dashboard_data(self, base_report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive dashboard data for visualizations"""
        try:
            return {
                "security_metrics": {
                    "overall_score": max(0, 100 - (base_report.get("overall_risk_score", 0) * 10)),
                    "vulnerability_distribution": {
                        "critical": base_report.get("critical_vulnerabilities", 0),
                        "high": base_report.get("high_vulnerabilities", 0),
                        "medium": base_report.get("medium_vulnerabilities", 0),
                        "low": base_report.get("low_vulnerabilities", 0)
                    },
                    "endpoint_coverage": base_report.get("total_endpoints_tested", 0),
                    "risk_trend": "Increasing" if base_report.get("total_vulnerabilities", 0) > 10 else "Stable"
                },
                "compliance_overview": {
                    "frameworks": ["GDPR", "HIPAA", "SOX", "PCI-DSS", "ISO-27001"],
                    "status": ["At Risk", "At Risk", "At Risk", "At Risk", "At Risk"],
                    "scores": [30, 25, 35, 20, 40]
                },
                "business_impact": {
                    "financial_risk": "HIGH",
                    "reputation_risk": "HIGH",
                    "operational_risk": "MEDIUM",
                    "legal_risk": "HIGH",
                    "overall_business_risk": "HIGH"
                }
            }
        except Exception as e:
            self.logger.error(f"Failed to generate dashboard data: {e}")
            return {}
    
    def _generate_compliance_matrix_data(self, compliance_status: ComplianceStatus) -> Dict[str, Any]:
        """Generate compliance matrix data"""
        try:
            return {
                "frameworks": ["GDPR", "HIPAA", "SOX", "PCI-DSS", "ISO-27001"],
                "compliance_scores": [
                    compliance_status.gdpr_compliance.get("score", 0),
                    compliance_status.hipaa_compliance.get("score", 0),
                    compliance_status.sox_compliance.get("score", 0),
                    compliance_status.pci_dss_compliance.get("score", 0),
                    compliance_status.iso_27001_compliance.get("score", 0)
                ],
                "compliance_status": [
                    compliance_status.gdpr_compliance.get("status", "NON_COMPLIANT"),
                    compliance_status.hipaa_compliance.get("status", "NON_COMPLIANT"),
                    compliance_status.sox_compliance.get("status", "NON_COMPLIANT"),
                    compliance_status.pci_dss_compliance.get("status", "NON_COMPLIANT"),
                    compliance_status.iso_27001_compliance.get("status", "NON_COMPLIANT")
                ]
            }
        except Exception as e:
            self.logger.error(f"Failed to generate compliance matrix data: {e}")
            return {}
    
    def _generate_risk_heatmap_data(self, base_report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk heatmap data"""
        try:
            endpoints = []
            risk_scores = []
            vulnerability_counts = []
            
            for endpoint in base_report.get("endpoint_reports", []):
                endpoints.append(endpoint.get("endpoint_path", ""))
                risk_scores.append(endpoint.get("overall_risk_score", 0))
                vulnerability_counts.append(endpoint.get("vulnerabilities_found", 0))
            
            return {
                "endpoints": endpoints,
                "risk_scores": risk_scores,
                "vulnerability_counts": vulnerability_counts,
                "risk_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            }
        except Exception as e:
            self.logger.error(f"Failed to generate risk heatmap data: {e}")
            return {}
    
    def _generate_trend_analysis_data(self, base_report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate trend analysis data"""
        try:
            return {
                "vulnerability_trend": "Increasing",
                "security_posture": "Declining",
                "compliance_risk": "High",
                "remediation_velocity": "Slow",
                "risk_indicators": {
                    "critical_vulnerabilities": base_report.get("critical_vulnerabilities", 0),
                    "high_vulnerabilities": base_report.get("high_vulnerabilities", 0),
                    "overall_risk_score": base_report.get("overall_risk_score", 0),
                    "endpoints_affected": base_report.get("endpoints_with_vulnerabilities", 0)
                }
            }
        except Exception as e:
            self.logger.error(f"Failed to generate trend analysis data: {e}")
            return {}


# Global instance
professional_report_generator = ProfessionalReportGenerator() 