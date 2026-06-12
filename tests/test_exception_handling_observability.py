"""
Regression tests for exception handling observability improvements.

This test suite verifies that infrastructure failures are properly logged
while preserving fault tolerance behavior.
"""

import asyncio
from unittest.mock import Mock, patch

import pytest


class TestResourceManagerAuditObservability:
    """Test resource manager audit failure observability."""

    def test_resource_manager_audit_failure_logged(self):
        """Verify resource manager audit failures are logged with debug level."""
        with patch("src.runtime.resources.resource_manager.log_audit_event") as mock_audit:
            mock_audit.side_effect = Exception("Audit system down")

            with patch("src.runtime.resources.resource_manager.logger") as mock_logger:
                from src.runtime.resources.resource_manager import _audit_resource_event

                _audit_resource_event("test_event", key="value")

                mock_logger.debug.assert_called_once()
                call_args = mock_logger.debug.call_args

                assert "Resource audit recording failed" in call_args[0][0]
                assert call_args[1]["exc_info"] is True


class TestConfigReloadAuditObservability:
    """Test config reload audit failure observability."""

    def test_config_reload_audit_failure_logged(self):
        """Verify config reload audit failures are logged with debug level."""
        from src.configuration.config_reload import ConfigReloadManager

        registry = Mock()
        audit_logger = Mock()
        audit_logger.side_effect = Exception("Audit system down")

        manager = ConfigReloadManager(registry, audit_logger)

        with patch("src.configuration.config_reload.logger") as mock_logger:
            manager._audit("test_event", "info", key="value")

            mock_logger.debug.assert_called_once()
            call_args = mock_logger.debug.call_args

            assert "Configuration audit recording failed" in call_args[0][0]
            assert call_args[1]["exc_info"] is True


class TestEventDispatcherObservability:
    """Test event dispatcher failure observability."""

    @pytest.mark.anyio
    async def test_event_dispatch_failure_logged(self):
        """Verify event dispatch failures are logged with exception level."""
        from src.runtime.events.dispatcher import EventDispatcher
        from src.runtime.events.event_bus import RuntimeEventBus
        from src.runtime.events.event_types import RuntimeEvent

        bus = Mock(spec=RuntimeEventBus)
        bus.publish.side_effect = Exception("Event bus error")

        dispatcher = EventDispatcher(bus)

        await dispatcher.start()

        try:
            with patch("src.runtime.events.dispatcher.logger") as mock_logger:
                event = Mock(spec=RuntimeEvent)

                dispatcher.dispatch(event)

                # Allow dispatcher loop to process the queued event
                await asyncio.sleep(0.1)

                mock_logger.exception.assert_called()

                call_args = mock_logger.exception.call_args
                assert "Event dispatch failed" in call_args[0][0]

        finally:
            await dispatcher.stop()