from contextvars import ContextVar
tenant_id = ContextVar("tenant_id", default=None)
