"""
Path management for PolluTaint data, results, and logs.

This module provides a centralized way to manage all file paths used by
the tool, ensuring consistent organization of crawled data, analysis results,
and log files.
"""

from pathlib import Path
from datetime import datetime
from typing import Optional


class PathManager:
    """
    Manages all file paths for PolluTaint.
    
    Provides a consistent structure for organizing:
    - Crawled code sources
    - Analysis results
    - Log files
    """
    
    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize path manager.
        
        Args:
            base_dir: Base directory for all PolluTaint data.
                     If None, uses current working directory.
        """
        if base_dir is None:
            base_dir = Path.cwd()
        
        self.base_dir = Path(base_dir)
        
        # Main directories
        self.data_dir = self.base_dir / "data"
        self.results_dir = self.base_dir / "results"
        self.logs_dir = self.base_dir / "logs"
        
        # Data subdirectories
        self.crawled_dir = self.data_dir / "crawled"
        self.local_dir = self.data_dir / "local"
        
        # Results subdirectories
        self.crawl_results_dir = self.results_dir / "crawl"
        self.batch_results_dir = self.results_dir / "batch"
        self.analyze_results_dir = self.results_dir / "analyze"
        
        # Create directories
        self._ensure_directories()
    
    def _ensure_directories(self) -> None:
        """Create all necessary directories if they don't exist."""
        directories = [
            self.data_dir,
            self.results_dir,
            self.logs_dir,
            self.crawled_dir,
            self.local_dir,
            self.crawl_results_dir,
            self.batch_results_dir,
            self.analyze_results_dir,
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def get_crawl_session_dir(self, timestamp: Optional[str] = None) -> Path:
        """
        Get directory for a crawl session.
        
        Args:
            timestamp: Timestamp string (YYYY-MM-DD_HH-MM-SS). If None, uses current time.
            
        Returns:
            Path to crawl session directory
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        session_dir = self.crawled_dir / timestamp
        session_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sources subdirectory
        sources_dir = session_dir / "sources"
        sources_dir.mkdir(parents=True, exist_ok=True)
        
        return session_dir
    
    def get_crawl_sources_dir(self, timestamp: Optional[str] = None) -> Path:
        """
        Get sources directory for a crawl session.
        
        Args:
            timestamp: Timestamp string. If None, uses current time.
            
        Returns:
            Path to sources directory
        """
        session_dir = self.get_crawl_session_dir(timestamp)
        return session_dir / "sources"
    
    def get_crawl_metadata_file(self, timestamp: Optional[str] = None) -> Path:
        """
        Get metadata file path for a crawl session.
        
        Args:
            timestamp: Timestamp string. If None, uses current time.
            
        Returns:
            Path to metadata.json file
        """
        session_dir = self.get_crawl_session_dir(timestamp)
        return session_dir / "metadata.json"
    
    def get_latest_crawl_dir(self) -> Optional[Path]:
        """
        Get the latest crawl session directory.
        
        Returns:
            Path to latest crawl directory, or None if no crawls exist
        """
        if not self.crawled_dir.exists():
            return None
        
        # Find all timestamp directories
        sessions = [
            d for d in self.crawled_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]
        
        if not sessions:
            return None
        
        # Sort by name (timestamp) and return latest
        sessions.sort(reverse=True)
        return sessions[0]
    
    def get_crawl_result_dir(self, timestamp: Optional[str] = None) -> Path:
        """
        Get directory for crawl analysis results.
        
        Args:
            timestamp: Timestamp string. If None, uses current time.
            
        Returns:
            Path to result directory
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        result_dir = self.crawl_results_dir / timestamp
        result_dir.mkdir(parents=True, exist_ok=True)
        return result_dir
    
    def get_batch_result_dir(self, timestamp: Optional[str] = None) -> Path:
        """
        Get directory for batch analysis results.
        
        Args:
            timestamp: Timestamp string. If None, uses current time.
            
        Returns:
            Path to result directory
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        result_dir = self.batch_results_dir / timestamp
        result_dir.mkdir(parents=True, exist_ok=True)
        return result_dir
    
    def get_analyze_result_file(self, input_name: str, timestamp: Optional[str] = None) -> Path:
        """
        Get result file path for analyze command.
        
        Args:
            input_name: Name of the input file/directory (sanitized)
            timestamp: Timestamp string. If None, uses current time.
            
        Returns:
            Path to result file
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Sanitize input name for filename
        safe_name = input_name.replace("/", "_").replace("\\", "_").replace(" ", "_")
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in ("_", "-", "."))[:50]
        
        result_dir = self.analyze_results_dir / timestamp
        result_dir.mkdir(parents=True, exist_ok=True)
        
        return result_dir / f"{safe_name}_results.json"
    
    def get_log_file(self, log_type: str = "main") -> Path:
        """
        Get log file path.
        
        Args:
            log_type: Type of log (e.g., 'main', 'crawl', 'batch')
            
        Returns:
            Path to log file
        """
        timestamp = datetime.now().strftime("%Y-%m-%d")
        return self.logs_dir / f"{log_type}_{timestamp}.log"
    
    def create_latest_symlink(self, target_dir: Path, link_name: str) -> None:
        """
        Create a symlink to the latest directory.
        
        Args:
            target_dir: Directory to link to
            link_name: Name of the symlink
        """
        parent = target_dir.parent
        link_path = parent / link_name
        
        # Remove existing symlink if it exists
        if link_path.exists() or link_path.is_symlink():
            link_path.unlink()
        
        # Create new symlink
        try:
            link_path.symlink_to(target_dir.name)
        except OSError:
            # Symlinks might not work on all systems, skip silently
            pass


# Global path manager instance
_path_manager: Optional[PathManager] = None


def get_path_manager(base_dir: Optional[Path] = None) -> PathManager:
    """
    Get or create the global path manager instance.
    
    Args:
        base_dir: Base directory. Only used on first call.
        
    Returns:
        PathManager instance
    """
    global _path_manager
    if _path_manager is None:
        _path_manager = PathManager(base_dir)
    return _path_manager


def set_path_manager(path_manager: PathManager) -> None:
    """
    Set the global path manager instance.
    
    Args:
        path_manager: PathManager instance to use
    """
    global _path_manager
    _path_manager = path_manager

