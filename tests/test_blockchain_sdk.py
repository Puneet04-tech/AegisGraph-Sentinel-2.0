import os
import json
import pytest
from src.blockchain_evidence.gateway import FabricGatewayClient
from src.features.blockchain_evidence import BlockchainEvidenceManager

def test_fabric_gateway_simulation(tmp_path):
    profile_data = {"name": "test-network", "x-org": "org1"}
    profile_file = tmp_path / "connection.json"
    profile_file.write_text(json.dumps(profile_data))
    
    client = FabricGatewayClient(str(profile_file))
    tx_id = client.invoke_chaincode("chan", "cc", "invoke", ["arg1"])
    assert len(tx_id) == 64
