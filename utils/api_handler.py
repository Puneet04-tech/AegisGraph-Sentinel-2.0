"""
API error handling and logging utilities.
Ensures API calls are properly logged and don't fail silently with None returns.
"""

import logging
from functools import wraps
from typing import Callable, Optional, Any, Dict
import traceback

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Raised when API call fails."""
    pass


class APILogger:
    """Logger for API operations."""

    @staticmethod
    def log_request(endpoint: str, method: str, params: Dict = None):
        """Log API request."""
        params_str = str(params) if params else "no params"
        logger.info(f"API Request: {method} {endpoint} - {params_str}")

    @staticmethod
    def log_response(endpoint: str, status_code: int, response_size: int):
        """Log API response."""
        logger.info(f"API Response: {endpoint} - Status {status_code} - Size {response_size} bytes")

    @staticmethod
    def log_error(endpoint: str, error: Exception):
        """Log API error with full traceback."""
        logger.error(f"API Error at {endpoint}: {str(error)}")
        logger.debug(f"Traceback: {traceback.format_exc()}")


def handle_api_call(
    endpoint: str = "unknown",
    default_return: Optional[Any] = None,
    raise_on_error: bool = True
):
    """
    Decorator for API calls with error handling and logging.

    Args:
        endpoint: API endpoint name for logging
        default_return: Value to return if error occurs (if not raising)
        raise_on_error: Whether to raise exception or return default

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                APILogger.log_request(endpoint, func.__name__, kwargs)
                result = func(*args, **kwargs)

                if result is None:
                    error_msg = f"API call returned None: {endpoint}"
                    logger.warning(error_msg)
                    if raise_on_error:
                        raise APIError(error_msg)
                    return default_return

                logger.debug(f"API call successful: {endpoint}")
                return result

            except Exception as e:
                APILogger.log_error(endpoint, e)
                if raise_on_error:
                    raise APIError(f"API call failed: {str(e)}") from e
                return default_return

        return wrapper
    return decorator


class APIClient:
    """
    Base API client with error handling and logging.
    """

    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize API client.

        Args:
            base_url: Base URL for API
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        logger.info(f"Initializing API client for {base_url}")

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """
        Make API request with error handling.

        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Additional request parameters

        Returns:
            Response data or raises APIError

        Raises:
            APIError: If request fails
        """
        try:
            import requests

            url = f"{self.base_url}/{endpoint}"
            logger.debug(f"Making {method} request to {url}")

            response = requests.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )

            # Log response
            APILogger.log_response(endpoint, response.status_code, len(response.content))

            # Check for HTTP errors
            response.raise_for_status()

            # Return JSON response
            return response.json()

        except Exception as e:
            APILogger.log_error(endpoint, e)
            raise APIError(f"API request failed: {str(e)}") from e

    def get(self, endpoint: str, params: Dict = None) -> Dict:
        """
        Make GET request.

        Args:
            endpoint: API endpoint
            params: Query parameters

        Returns:
            Response data
        """
        return self._make_request("GET", endpoint, params=params)

    def post(self, endpoint: str, data: Dict = None, json: Dict = None) -> Dict:
        """
        Make POST request.

        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON body

        Returns:
            Response data
        """
        return self._make_request("POST", endpoint, data=data, json=json)

    def put(self, endpoint: str, data: Dict = None, json: Dict = None) -> Dict:
        """
        Make PUT request.

        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON body

        Returns:
            Response data
        """
        return self._make_request("PUT", endpoint, data=data, json=json)

    def delete(self, endpoint: str) -> Dict:
        """
        Make DELETE request.

        Args:
            endpoint: API endpoint

        Returns:
            Response data
        """
        return self._make_request("DELETE", endpoint)


def safe_api_call(func: Callable, *args, **kwargs) -> Optional[Any]:
    """
    Execute API call with error handling and logging.

    Args:
        func: API function to call
        *args: Positional arguments
        **kwargs: Keyword arguments

    Returns:
        Function result or None if error occurs (logged)
    """
    try:
        logger.debug(f"Executing API call: {func.__name__}")
        result = func(*args, **kwargs)

        if result is None:
            logger.warning(f"API call {func.__name__} returned None")
            return None

        logger.info(f"API call {func.__name__} succeeded")
        return result

    except Exception as e:
        logger.error(f"API call {func.__name__} failed: {str(e)}")
        logger.debug(traceback.format_exc())
        return None


def validate_api_response(response: Dict, required_fields: list) -> bool:
    """
    Validate API response contains required fields.

    Args:
        response: API response data
        required_fields: List of required field names

    Returns:
        True if valid, raises APIError otherwise
    """
    if response is None:
        raise APIError("API response is None")

    if not isinstance(response, dict):
        raise APIError(f"API response is not a dictionary: {type(response)}")

    missing_fields = [f for f in required_fields if f not in response]
    if missing_fields:
        raise APIError(f"API response missing required fields: {missing_fields}")

    logger.debug("API response validation passed")
    return True
