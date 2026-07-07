import pytest
import socket
from unittest.mock import MagicMock, patch
from src.integrations.syslog.client import SyslogClient
from src.case_management.store import CaseStore
from src.case_management.models import CasePriority

def test_rfc5424_formatting() -> None:
    client = SyslogClient()
    formatted = client.format_rfc5424(
        severity=4,
        msg_id="CASE_ESCALATED",
        message="Case CASE_123 has been escalated",
        structured_data={"case_id": "CASE_123", "analyst_id": "ANALYST_1"},
    )
    
    # PRI for local0 (16) and severity (4) is 16 * 8 + 4 = 132
    assert formatted.startswith("<132>1 ")
    assert " aegisgraph-sentinel aegisgraph - CASE_ESCALATED " in formatted
    assert '[meta@42424 case_id="CASE_123" analyst_id="ANALYST_1"]' in formatted
    assert formatted.endswith("Case CASE_123 has been escalated")

@patch("socket.socket")
def test_syslog_udp_send(mock_socket_class) -> None:
    mock_socket_instance = MagicMock()
    mock_socket_class.return_value.__enter__.return_value = mock_socket_instance
    
    client = SyslogClient(host="syslog-server.local", port=514)
    success = client.log_event(
        msg_id="TEST_ALERT",
        message="A test syslog message",
    )
    
    assert success is True
    mock_socket_instance.sendto.assert_called_once()
    args, kwargs = mock_socket_instance.sendto.call_args
    message_bytes, destination = args
    assert b"TEST_ALERT" in message_bytes
    assert destination == ("syslog-server.local", 514)

def test_store_triggers_syslog() -> None:
    store = CaseStore()
    
    # Mock SyslogClient.log_event
    mock_log_event = MagicMock()
    store.syslog_client.log_event = mock_log_event
    
    # Create case should trigger _append_audit -> log_event
    case = store.create_case(
        transaction_id="tx_123",
        risk_score=0.85,
        decision="BLOCK",
        analyst_id="ANALYST_1",
        priority=CasePriority.HIGH,
    )
    
    mock_log_event.assert_called_once()
    _, kwargs = mock_log_event.call_args
    assert kwargs["msg_id"] == "CASE_CREATED"
    assert kwargs["metadata"]["case_id"] == case.case_id
    assert kwargs["metadata"]["analyst_id"] == "ANALYST_1"
