import os
import numpy as np
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

class FastONNXAnalyzer:
    """
    High-performance inference engine bypassing the Python GIL.
    Utilizes onnxruntime to execute the Biometric LSTM at C++ speeds.
    """
    def __init__(self, model_path="models/biometrics_lstm.onnx"):
        self.model_path = model_path
        self.is_loaded = False
        
        if ONNX_AVAILABLE and os.path.exists(self.model_path):
            # This spins up the C++ execution engine
            self.session = ort.InferenceSession(
                self.model_path, 
                providers=['CPUExecutionProvider']
            )
            self.is_loaded = True
            print(f"🚀 ONNX Runtime Initialized: Serving {model_path} at high speed.")
        else:
            print("⚠️ ONNX Runtime or artifact not found. API will require standard PyTorch fallback.")

    def analyze_sequence(self, flight_times, hold_times):
        """Executes the compiled graph in sub-millisecond time."""
        if not self.is_loaded:
            return 0.0

        # Standardize sequence length to 20
        seq_len = 20
        ft = (flight_times[:seq_len] + [0.0]*seq_len)[:seq_len]
        ht = (hold_times[:seq_len] + [0.0]*seq_len)[:seq_len]

        # Fast NumPy normalization
        ft_arr = np.array(ft)
        ht_arr = np.array(ht)
        ft_norm = (ft_arr - np.mean(ft_arr)) / (np.std(ft_arr) + 1e-6)
        ht_norm = (ht_arr - np.mean(ht_arr)) / (np.std(ht_arr) + 1e-6)

        # Shape: (1, 20, 2) - Float32 required by ONNX
        tensor_input = np.column_stack((ft_norm, ht_norm)).astype(np.float32)
        tensor_input = np.expand_dims(tensor_input, axis=0)

        # ⚡ Execute the C++ Graph (Zero Python GIL blocking)
        input_name = self.session.get_inputs()[0].name
        outputs = self.session.run(None, {input_name: tensor_input})
        
        # Return the raw probability float
        return float(outputs[0][0])

if __name__ == "__main__":
    analyzer = FastONNXAnalyzer()