"""
Resource management for ThreadPoolExecutor and other shared resources.
Ensures proper cleanup and prevents resource leaks on application restart.
"""

import atexit
import logging
from concurrent.futures import ThreadPoolExecutor
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


class ManagedThreadPool:
    """
    Managed ThreadPoolExecutor with proper lifecycle management.
    Ensures executor is properly shut down on application exit.
    """

    def __init__(self, max_workers: int = 10, thread_name_prefix: str = "worker"):
        """
        Initialize managed thread pool.

        Args:
            max_workers: Maximum number of worker threads
            thread_name_prefix: Prefix for worker thread names
        """
        self._lock = RLock()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._max_workers = max_workers
        self._thread_name_prefix = thread_name_prefix
        self._shutdown = False

        # Register cleanup on exit
        atexit.register(self.shutdown)

    def get_executor(self) -> ThreadPoolExecutor:
        """
        Get or create the thread pool executor.

        Returns:
            ThreadPoolExecutor instance
        """
        with self._lock:
            if self._shutdown:
                raise RuntimeError("ThreadPool has been shut down")

            if self._executor is None:
                logger.info(f"Creating ThreadPoolExecutor with {self._max_workers} workers")
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix=self._thread_name_prefix
                )

            return self._executor

    def shutdown(self, wait: bool = True):
        """
        Properly shut down the thread pool.

        Args:
            wait: Whether to wait for pending tasks
        """
        with self._lock:
            if self._executor is not None and not self._shutdown:
                logger.info("Shutting down ThreadPoolExecutor")
                try:
                    self._executor.shutdown(wait=wait)
                    logger.info("ThreadPoolExecutor shutdown complete")
                except Exception as e:
                    logger.error(f"Error during executor shutdown: {e}")
                finally:
                    self._executor = None
                    self._shutdown = True

    def __enter__(self):
        """Context manager entry."""
        return self.get_executor()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()


class ResourceRegistry:
    """
    Registry for managing application resources.
    Ensures all resources are properly cleaned up on shutdown.
    """

    def __init__(self):
        """Initialize resource registry."""
        self._resources = {}
        self._lock = RLock()
        atexit.register(self.cleanup_all)

    def register(self, name: str, resource):
        """
        Register a resource for cleanup.

        Args:
            name: Resource identifier
            resource: Resource object (should have close() or shutdown() method)
        """
        with self._lock:
            if name in self._resources:
                logger.warning(f"Overwriting existing resource: {name}")
            self._resources[name] = resource
            logger.debug(f"Registered resource: {name}")

    def get(self, name: str):
        """
        Get a registered resource.

        Args:
            name: Resource identifier

        Returns:
            Resource object or None
        """
        with self._lock:
            return self._resources.get(name)

    def cleanup_all(self):
        """
        Clean up all registered resources.
        """
        with self._lock:
            for name, resource in self._resources.items():
                try:
                    if hasattr(resource, 'shutdown'):
                        logger.info(f"Shutting down resource: {name}")
                        resource.shutdown()
                    elif hasattr(resource, 'close'):
                        logger.info(f"Closing resource: {name}")
                        resource.close()
                except Exception as e:
                    logger.error(f"Error cleaning up resource {name}: {e}")

            self._resources.clear()
            logger.info("All resources cleaned up")


# Global registry instance
_resource_registry = ResourceRegistry()


def get_resource_registry() -> ResourceRegistry:
    """Get the global resource registry."""
    return _resource_registry


def get_global_thread_pool(max_workers: int = 10) -> ThreadPoolExecutor:
    """
    Get or create the global thread pool.

    Args:
        max_workers: Maximum workers (used on first call only)

    Returns:
        ThreadPoolExecutor instance
    """
    registry = get_resource_registry()
    pool = registry.get("thread_pool")

    if pool is None:
        managed_pool = ManagedThreadPool(max_workers)
        registry.register("thread_pool", managed_pool)
        pool = managed_pool.get_executor()

    return pool


class ResourceContextManager:
    """
    Context manager for automatic resource cleanup.
    """

    def __init__(self, *resources):
        """
        Initialize with resources to manage.

        Args:
            *resources: Resource objects to clean up on exit
        """
        self.resources = resources

    def __enter__(self):
        """Context manager entry."""
        return self.resources if len(self.resources) > 1 else self.resources[0]

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - clean up all resources."""
        for resource in self.resources:
            try:
                if hasattr(resource, 'shutdown'):
                    resource.shutdown()
                elif hasattr(resource, 'close'):
                    resource.close()
            except Exception as e:
                logger.error(f"Error cleaning up resource: {e}")
