"""
Centralized Logging System

This module is a unified logging interface for the entire application.
All components should use this logger instead of creating their own.

Usage:
    from utils.logger import get_logger
    
    logger = get_logger(__name__)
    logger.info("Application started")
    logger.error("An error occurred", exc_info=True)
"""

import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
import json
import sys
import os
from typing import Optional, Dict, Any, List


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format.
    Useful for structured logging and log analysis.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: The log record to format
            
        Returns:
            JSON formatted log line
        """
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if provided
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data, ensure_ascii=False)


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with color support for console output.
    Makes logs easier to read in terminal.
    """
    
    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with colors.
        
        Args:
            record: The log record to format
            
        Returns:
            Colored formatted log line
        """
        color = self.COLORS.get(record.levelname, self.RESET)
        
        # Format: [TIME] [LEVEL] [MODULE:FUNCTION] Message
        log_format = (
            f"[{self._get_time(record.created)}] "
            f"{color}[{record.levelname:8}]{self.RESET} "
            f"[{record.module}:{record.funcName}] "
            f"{record.getMessage()}"
        )
        
        # Add exception info if present
        if record.exc_info:
            log_format += f"\n{self.formatException(record.exc_info)}"
        
        return log_format
    
    @staticmethod
    def _get_time(timestamp: float) -> str:
        """Format timestamp as HH:MM:SS"""
        return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")


class ProjectLogger:
    """
    Centralized logger for the entire project.
    
    Features:
    - Multiple handlers (console, file, structured JSON)
    - Configurable log levels
    - Automatic log rotation
    - Colored console output
    - JSON structured logging
    """
    
    _instance: Optional["ProjectLogger"] = None
    _loggers: Dict[str, logging.Logger] = {}
    
    def __init__(
        self,
        log_dir: str = "./database/logger",
        console_level: str = "INFO",
        file_level: str = "DEBUG",
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
    ):
        """
        Initialize the project logger.
        
        Args:
            log_dir: Directory for log files
            console_level: Logging level for console output
            file_level: Logging level for file output
            max_bytes: Maximum size of log file before rotation (bytes)
            backup_count: Number of backup log files to keep
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.console_level = getattr(logging, console_level.upper(), logging.INFO)
        self.file_level = getattr(logging, file_level.upper(), logging.DEBUG)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get or create a logger with the given name.
        
        Args:
            name: Logger name (usually __name__)
            
        Returns:
            Configured logger instance
        """
        if name in self._loggers:
            return self._loggers[name]
        
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)  # Set to lowest level, handlers will filter
        
        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()
        
        # Add console handler with colored output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.console_level)
        console_formatter = ColoredFormatter()
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # Add rotating file handler for general logs
        general_log_file = self.log_dir / "general.log"
        general_handler = logging.handlers.RotatingFileHandler(
            general_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        general_handler.setLevel(self.file_level)
        general_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        general_handler.setFormatter(general_formatter)
        logger.addHandler(general_handler)
        
        # Add rotating file handler for errors only
        error_log_file = self.log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(general_formatter)
        logger.addHandler(error_handler)
        
        # Add JSON structured logging file
        json_log_file = self.log_dir / "structured.json"
        json_handler = logging.handlers.RotatingFileHandler(
            json_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        json_handler.setLevel(self.file_level)
        json_handler.setFormatter(JSONFormatter())
        logger.addHandler(json_handler)
        
        # Prevent propagation to root logger
        logger.propagate = False
        
        self._loggers[name] = logger
        return logger
    
    def add_context_filter(self, logger_name: str, context: Dict[str, Any]) -> None:
        """
        Add context information to a specific logger.
        
        Args:
            logger_name: Name of the logger
            context: Dictionary of context information to add to all logs
        """
        logger = self._loggers.get(logger_name)
        if logger:
            # This would require a custom filter implementation
            # For now, we'll keep it simple
            pass
    
    @classmethod
    def get_instance(cls) -> "ProjectLogger":
        """
        Get the singleton instance of the project logger.
        
        Returns:
            ProjectLogger instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


# Global logger instance
_project_logger = ProjectLogger.get_instance()


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger for a module.
    
    This is the primary function to use throughout the application.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
        
    Example:
        from utils.logger import get_logger
        
        logger = get_logger(__name__)
        logger.info("Processing started")
        logger.error("An error occurred", exc_info=True)
    """
    return _project_logger.get_logger(name)


def configure_logger(
    log_dir: str = "./database/logger",
    console_level: str = "INFO",
    file_level: str = "DEBUG",
) -> None:
    """
    Configure the global project logger.
    
    Call this once during application startup.
    
    Args:
        log_dir: Directory for log files
        console_level: Console logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        file_level: File logging level
        
    Example:
        from utils.logger import configure_logger
        
        configure_logger(
            console_level="INFO",
            file_level="DEBUG"
        )
    """
    global _project_logger
    _project_logger = ProjectLogger(
        log_dir=log_dir,
        console_level=console_level,
        file_level=file_level,
    )


class AgentLogger:
    """Centralized logger for agent system task tracking and conversation history"""
    
    def __init__(self, session_id: str, output_dir: str = "logs"):
        """
        Initialize Agent Logger
        
        Args:
            session_id: Unique identifier for the session
            output_dir: Directory to save session logs
        """
        self.session_id = session_id
        self.output_dir = output_dir
        self.logger = get_logger(f"AgentSystem.{session_id}")
        
        # Session tracking
        self.session_start_time = datetime.now()
        self.conversation_history: List[Dict[str, Any]] = []
        self.task_logs: List[Dict[str, Any]] = []
        self.active_tasks: Dict[str, Dict[str, Any]] = {}
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        self.logger.info(f"AgentLogger initialized for session: {session_id}")
    
    def log_user_query(self, query: str) -> str:
        """Log a user query and return query ID"""
        query_id = f"q_{len(self.conversation_history)}_{int(datetime.now().timestamp() * 1000)}"
        
        entry = {
            "type": "user_query",
            "timestamp": datetime.now().isoformat(),
            "query_id": query_id,
            "content": query
        }
        
        self.conversation_history.append(entry)
        self.logger.info(f"User query received: {query_id}")
        
        return query_id
    
    def log_system_response(self, query_id: str, response: str, agent_name: str = "system"):
        """Log a system response to user query"""
        entry = {
            "type": "system_response",
            "timestamp": datetime.now().isoformat(),
            "query_id": query_id,
            "agent_name": agent_name,
            "content": response
        }
        
        self.conversation_history.append(entry)
        self.logger.info(f"System response generated for {query_id} by {agent_name}")
    
    def start_agent_task(self, agent_name: str, task_type: str, task_data: Dict[str, Any]) -> str:
        """
        Start tracking an agent task
        
        Args:
            agent_name: Name of the agent (e.g., 'VisionAgent', 'VulnReportAgent')
            task_type: Type of task (e.g., 'scan', 'analysis', 'reporting')
            task_data: Task-specific data dictionary
            
        Returns:
            task_id for later reference
        """
        task_id = f"t_{agent_name}_{len(self.task_logs)}_{int(datetime.now().timestamp() * 1000)}"
        
        task_log = {
            "task_id": task_id,
            "agent_name": agent_name,
            "task_type": task_type,
            "start_time": datetime.now().isoformat(),
            "status": "in_progress",
            "data": task_data,
            "progress": [],
            "end_time": None,
            "result": None,
            "error": None
        }
        
        self.active_tasks[task_id] = task_log
        self.task_logs.append(task_log)
        
        self.logger.info(f"Agent task started: {task_id} ({agent_name}/{task_type})")
        
        return task_id
    
    def log_task_progress(self, task_id: str, message: str, details: Optional[Dict] = None):
        """Log progress for an ongoing task"""
        if task_id not in self.active_tasks:
            self.logger.warning(f"Progress logged for non-existent task: {task_id}")
            return
        
        progress_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "details": details or {}
        }
        
        self.active_tasks[task_id]["progress"].append(progress_entry)
        self.logger.info(f"Task progress: {task_id} - {message}")
    
    def end_agent_task(self, task_id: str, status: str = "completed", 
                      result: Optional[Any] = None, error: Optional[str] = None):
        """
        Mark an agent task as complete
        
        Args:
            task_id: Task ID returned from start_agent_task
            status: Final status ('completed', 'failed', 'cancelled')
            result: Task result data
            error: Error message if failed
        """
        if task_id not in self.active_tasks:
            self.logger.warning(f"End signal for non-existent task: {task_id}")
            return
        
        task_log = self.active_tasks.pop(task_id)
        task_log["status"] = status
        task_log["end_time"] = datetime.now().isoformat()
        task_log["result"] = result
        task_log["error"] = error
        
        # Calculate duration
        start_time = datetime.fromisoformat(task_log["start_time"])
        end_time = datetime.fromisoformat(task_log["end_time"])
        duration = (end_time - start_time).total_seconds()
        task_log["duration_seconds"] = duration
        
        log_level = logging.ERROR if status == "failed" else logging.INFO
        self.logger.log(log_level, f"Task completed: {task_id} (status={status}, duration={duration:.2f}s)")
    
    def save_session_log(self) -> str:
        """
        Save complete session log to file
        
        Returns:
            Path to the saved log file
        """
        session_duration = (datetime.now() - self.session_start_time).total_seconds()
        
        session_log = {
            "session_id": self.session_id,
            "session_start": self.session_start_time.isoformat(),
            "session_end": datetime.now().isoformat(),
            "session_duration_seconds": session_duration,
            "total_queries": sum(1 for h in self.conversation_history if h["type"] == "user_query"),
            "total_responses": sum(1 for h in self.conversation_history if h["type"] == "system_response"),
            "total_tasks": len(self.task_logs),
            "conversation_history": self.conversation_history,
            "task_logs": self.task_logs
        }
        
        # Save to JSON file
        log_filename = f"{self.session_id}_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        log_path = os.path.join(self.output_dir, log_filename)
        
        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(session_log, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Session log saved: {log_path}")
            
            return log_path
        except Exception as e:
            self.logger.error(f"Failed to save session log: {str(e)}", exc_info=True)
            raise

