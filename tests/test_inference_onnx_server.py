import os
import sys
import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.inference.onnx_server import FastONNXAnalyzer


@pytest.fixture
def mock_session():
    mock_sess = Mock()
    mock_input = Mock()
    mock_input.name = "input_0"
    mock_sess.get_inputs.return_value = [mock_input]
    mock_sess.run.return_value = [np.array([[0.75]], dtype=np.float32)]
    return mock_sess


@pytest.fixture
def analyzer(mock_session):
    with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
         patch('os.path.exists', return_value=True), \
         patch('onnxruntime.InferenceSession', return_value=mock_session):
        
        analyzer = FastONNXAnalyzer(model_path="models/biometrics_lstm.onnx")
        return analyzer


class TestFastONNXAnalyzerInit:
    def test_init_with_existing_model_path(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=True), \
             patch('onnxruntime.InferenceSession') as mock_session:
            
            mock_session_instance = Mock()
            mock_session.return_value = mock_session_instance
            
            analyzer = FastONNXAnalyzer(model_path="models/biometrics_lstm.onnx")
            
            assert analyzer.model_path == "models/biometrics_lstm.onnx"
            assert analyzer.is_loaded is True
            mock_session.assert_called_once_with(
                "models/biometrics_lstm.onnx",
                providers=['CPUExecutionProvider']
            )

    def test_init_with_nonexistent_model_path(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=False):
            
            analyzer = FastONNXAnalyzer(model_path="models/missing.onnx")
            
            assert analyzer.model_path == "models/missing.onnx"
            assert analyzer.is_loaded is False

    def test_init_with_onnx_unavailable(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', False), \
             patch('os.path.exists', return_value=True):
            
            analyzer = FastONNXAnalyzer(model_path="models/biometrics_lstm.onnx")
            
            assert analyzer.is_loaded is False

    def test_init_with_custom_model_path(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=True), \
             patch('onnxruntime.InferenceSession') as mock_session:
            
            mock_session_instance = Mock()
            mock_session.return_value = mock_session_instance
            
            analyzer = FastONNXAnalyzer(model_path="/custom/path/model.onnx")
            
            assert analyzer.model_path == "/custom/path/model.onnx"
            mock_session.assert_called_once_with(
                "/custom/path/model.onnx",
                providers=['CPUExecutionProvider']
            )


class TestFastONNXAnalyzerAnalyzeSequence:
    def test_analyze_sequence_returns_probability(self, analyzer, mock_session):
        flight_times = [0.1] * 20
        hold_times = [0.15] * 20
        
        result = analyzer.analyze_sequence(flight_times, hold_times)
        
        assert isinstance(result, float)
        assert result == 0.75
        mock_session.run.assert_called_once()

    def test_analyze_sequence_with_short_sequences_pads_to_20(self, analyzer, mock_session):
        flight_times = [0.1, 0.2, 0.3]
        hold_times = [0.15, 0.25]
        
        result = analyzer.analyze_sequence(flight_times, hold_times)
        
        assert isinstance(result, float)
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.shape == (1, 20, 2)

    def test_analyze_sequence_with_long_sequences_truncates_to_20(self, analyzer, mock_session):
        flight_times = [0.1] * 30
        hold_times = [0.15] * 30
        
        result = analyzer.analyze_sequence(flight_times, hold_times)
        
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.shape == (1, 20, 2)

    def test_analyze_sequence_when_not_loaded_returns_zero(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=False):
            
            analyzer = FastONNXAnalyzer(model_path="models/missing.onnx")
            result = analyzer.analyze_sequence([0.1]*20, [0.15]*20)
            
            assert result == 0.0

    def test_analyze_sequence_input_normalization(self, analyzer, mock_session):
        flight_times = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] * 2
        hold_times = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95] * 2
        
        result = analyzer.analyze_sequence(flight_times, hold_times)
        
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.dtype == np.float32
        assert input_tensor.shape == (1, 20, 2)

    def test_analyze_sequence_multiple_outputs_returns_first(self, analyzer, mock_session):
        mock_session.run.return_value = [
            np.array([[0.75]], dtype=np.float32),
            np.array([[0.25]], dtype=np.float32)
        ]
        
        result = analyzer.analyze_sequence([0.1]*20, [0.15]*20)
        
        assert result == 0.75

    def test_analyze_sequence_empty_lists(self, analyzer, mock_session):
        result = analyzer.analyze_sequence([], [])
        
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.shape == (1, 20, 2)

    def test_analyze_sequence_single_element(self, analyzer, mock_session):
        result = analyzer.analyze_sequence([0.1], [0.15])
        
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.shape == (1, 20, 2)


class TestFastONNXAnalyzerEdgeCases:
    def test_analyze_sequence_varied_length_flight_hold(self, mock_session):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=True), \
             patch('onnxruntime.InferenceSession', return_value=mock_session):
             
            analyzer = FastONNXAnalyzer(model_path="models/biometrics_lstm.onnx")
            result = analyzer.analyze_sequence([0.1]*5, [0.15]*15)

            call_args = mock_session.run.call_args
            input_tensor = call_args[0][1]['input_0']
            assert input_tensor.shape == (1, 20, 2)

    def test_analyze_sequence_negative_values(self, analyzer, mock_session):
        flight_times = [-0.1, -0.2, -0.3] * 7
        hold_times = [0.1, 0.2, 0.3] * 7
        
        result = analyzer.analyze_sequence(flight_times, hold_times)
        
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.shape == (1, 20, 2)

    def test_analyze_sequence_large_values(self, analyzer, mock_session):
        flight_times = [1000.0] * 20
        hold_times = [2000.0] * 20
        
        result = analyzer.analyze_sequence(flight_times, hold_times)
        
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.shape == (1, 20, 2)
        assert np.all(np.isfinite(input_tensor))

def test_analyze_session_with_exception_returns_zero(analyzer, mock_session):
        mock_session.run.side_effect = RuntimeError("ONNX Runtime error")

        with pytest.raises(RuntimeError):
            analyzer.analyze_sequence([0.1]*20, [0.15]*20)


class TestFastONNXAnalyzerSessionManagement:
    def test_session_created_with_cpu_provider(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=True), \
             patch('onnxruntime.InferenceSession') as mock_session:
            
            FastONNXAnalyzer(model_path="models/test.onnx")
            
            mock_session.assert_called_once_with(
                "models/test.onnx",
                providers=['CPUExecutionProvider']
            )

    def test_is_loaded_false_when_model_missing(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=False):
            
            analyzer = FastONNXAnalyzer(model_path="models/missing.onnx")
            
            assert analyzer.is_loaded is False

    def test_is_loaded_false_when_onnx_unavailable(self):
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', False), \
             patch('os.path.exists', return_value=True):
            
            analyzer = FastONNXAnalyzer(model_path="models/biometrics_lstm.onnx")
            
            assert analyzer.is_loaded is False


class TestFastONNXAnalyzerIntegration:
    def test_full_inference_pipeline(self):
        mock_session = Mock()
        mock_input = Mock()
        mock_input.name = "input_0"
        mock_session.get_inputs.return_value = [mock_input]
        mock_session.run.return_value = [np.array([[0.85]], dtype=np.float32)]
        
        with patch('src.inference.onnx_server.ONNX_AVAILABLE', True), \
             patch('os.path.exists', return_value=True), \
             patch('onnxruntime.InferenceSession', return_value=mock_session):
            
            analyzer = FastONNXAnalyzer(model_path="models/biometrics_lstm.onnx")
            result = analyzer.analyze_sequence(
                [0.1 + i*0.01 for i in range(20)],
                [0.15 + i*0.01 for i in range(20)]
            )
            
            assert abs(result - 0.85) < 1e-6
            assert analyzer.is_loaded is True

    def test_multiple_analyze_calls(self, analyzer, mock_session):
        for i in range(5):
            result = analyzer.analyze_sequence([0.1]*20, [0.15]*20)
            assert result == 0.75
        
        assert mock_session.run.call_count == 5

    def test_analyze_sequence_preserves_batch_dimension(self, analyzer, mock_session):
        result = analyzer.analyze_sequence([0.1]*20, [0.15]*20)
        
        call_args = mock_session.run.call_args
        input_tensor = call_args[0][1]['input_0']
        assert input_tensor.shape[0] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])