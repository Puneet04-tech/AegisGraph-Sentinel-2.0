"""
Observability middleware for AegisGraph Sentinel.
"""

import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.observability.telemetry import (
    request_count,
    fraud_request_latency_seconds,
    error_count
)

class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to record standard Prometheus metrics for incoming API requests."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        try:
            response = await call_next(request)
            status = str(response.status_code)
            
            # Record metrics
            request_count.labels(status=status).inc()
            
            # If it's a fraud check endpoint, record specific latency
            if request.url.path == "/api/v1/fraud/check":
                fraud_request_latency_seconds.observe(time.time() - start_time)
                
            return response
            
        except Exception as e:
            error_count.labels(type=e.__class__.__name__).inc()
            request_count.labels(status="500").inc()
            raise
