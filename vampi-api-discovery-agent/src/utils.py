"""
Utility functions for VAmPI API Discovery Agent.

This module provides helper functions for file operations, backup management,
and other common utilities used throughout the application.
"""

import os
import json
import shutil
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union
from urllib.parse import urljoin, urlparse
import time
import random

# Handle both direct execution and module import
try:
    from .models import APIDiscoveryResult, DiscoveryConfig
except ImportError:
    from models import APIDiscoveryResult, DiscoveryConfig


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Set up logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("vampi_discovery")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def backup_file_if_exists(file_path: Union[str, Path]) -> Optional[str]:
    """
    Backup a file if it exists by creating a timestamped backup.
    
    Args:
        file_path: Path to the file to backup
        
    Returns:
        Path to the backup file if created, None if no backup was needed
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        return None
    
    # Create backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = file_path.parent / f"{file_path.stem}.bak.{timestamp}{file_path.suffix}"
    
    try:
        shutil.copy2(file_path, backup_path)
        return str(backup_path)
    except Exception as e:
        logging.error(f"Failed to backup file {file_path}: {e}")
        return None


def safe_write_file(file_path: Union[str, Path], content: str, backup: bool = True) -> bool:
    """
    Safely write content to a file, optionally backing up existing content.
    
    Args:
        file_path: Path to the file to write
        content: Content to write to the file
        backup: Whether to backup existing file
        
    Returns:
        True if successful, False otherwise
    """
    file_path = Path(file_path)
    
    try:
        # Create backup if requested and file exists
        backup_path = None
        if backup and file_path.exists():
            backup_path = backup_file_if_exists(file_path)
        
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logging.info(f"Successfully wrote file: {file_path}")
        if backup_path:
            logging.info(f"Backup created at: {backup_path}")
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to write file {file_path}: {e}")
        return False


def safe_write_json(file_path: Union[str, Path], data: Any, backup: bool = True, indent: int = 2) -> bool:
    """
    Safely write JSON data to a file, optionally backing up existing content.
    
    Args:
        file_path: Path to the file to write
        data: Data to serialize to JSON
        backup: Whether to backup existing file
        indent: JSON indentation level
        
    Returns:
        True if successful, False otherwise
    """
    try:
        json_content = json.dumps(data, indent=indent, default=str, ensure_ascii=False)
        return safe_write_file(file_path, json_content, backup)
    except Exception as e:
        logging.error(f"Failed to serialize data to JSON: {e}")
        return False


def load_config_from_env() -> DiscoveryConfig:
    """
    Load discovery configuration from environment variables.
    
    Returns:
        DiscoveryConfig instance with values from environment
    """
    return DiscoveryConfig(
        base_url=os.getenv("VAMPI_BASE_URL", "http://localhost:5000"),
        timeout=int(os.getenv("VAMPI_DISCOVERY_TIMEOUT", "30")),
        max_retries=int(os.getenv("DISCOVERY_MAX_RETRIES", "3")),
        rate_limit_delay=float(os.getenv("VAMPI_RATE_LIMIT_DELAY", "1.0")),
        user_agent=os.getenv("DISCOVERY_USER_AGENT", "VAmPI-Discovery-Agent/1.0"),
        respect_rate_limits=os.getenv("RESPECT_RATE_LIMITS", "true").lower() == "true"
    )


def normalize_url(base_url: str, path: str) -> str:
    """
    Normalize a URL by joining base URL with path.
    
    Args:
        base_url: Base URL
        path: Path to append
        
    Returns:
        Normalized full URL
    """
    if not path.startswith('/'):
        path = '/' + path
    return urljoin(base_url, path)


def extract_path_parameters(path: str) -> list:
    """
    Extract path parameters from a URL path.
    
    Args:
        path: URL path (e.g., "/users/{user_id}/books/{book_id}")
        
    Returns:
        List of path parameter names
    """
    import re
    pattern = r'\{([^}]+)\}'
    return re.findall(pattern, path)


def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url: URL string to validate
        
    Returns:
        True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def rate_limit_delay(min_delay: float = 0.5, max_delay: float = 2.0) -> None:
    """
    Implement rate limiting delay between requests.
    
    Args:
        min_delay: Minimum delay in seconds
        max_delay: Maximum delay in seconds
    """
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing or replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import re
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(' .')
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    return sanitized


def create_output_directory(output_dir: str) -> Path:
    """
    Create output directory if it doesn't exist.
    
    Args:
        output_dir: Output directory path
        
    Returns:
        Path object for the output directory
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def save_discovery_result(result: APIDiscoveryResult, output_dir: str, filename: str = None) -> Optional[str]:
    """
    Save discovery result to JSON file.
    
    Args:
        result: Discovery result to save
        output_dir: Output directory
        filename: Optional filename, defaults to timestamped name
        
    Returns:
        Path to saved file if successful, None otherwise
    """
    try:
        output_path = create_output_directory(output_dir)
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vampi_discovery_{timestamp}.json"
        
        # Sanitize filename
        filename = sanitize_filename(filename)
        if not filename.endswith('.json'):
            filename += '.json'
        
        file_path = output_path / filename
        
        # Save with backup
        if safe_write_json(file_path, result.dict(), backup=True):
            return str(file_path)
        else:
            return None
            
    except Exception as e:
        logging.error(f"Failed to save discovery result: {e}")
        return None


def load_discovery_result(file_path: Union[str, Path]) -> Optional[APIDiscoveryResult]:
    """
    Load discovery result from JSON file.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        APIDiscoveryResult instance if successful, None otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return APIDiscoveryResult(**data)
    except Exception as e:
        logging.error(f"Failed to load discovery result from {file_path}: {e}")
        return None


def format_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp for display.
    
    Args:
        timestamp: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def calculate_success_rate(total: int, successful: int) -> float:
    """
    Calculate success rate percentage.
    
    Args:
        total: Total number of attempts
        successful: Number of successful attempts
        
    Returns:
        Success rate as percentage (0.0 to 100.0)
    """
    if total == 0:
        return 0.0
    return (successful / total) * 100.0 