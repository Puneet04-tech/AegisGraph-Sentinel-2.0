import os
import torch
import logging
from src.inference.biometrics_lstm import BiometricLSTM

logger = logging.getLogger(__name__)

def compile_lstm_to_onnx():
    logger.info("⚙️ Initializing ONNX Compilation for Biometric LSTM...")
    
    # 1. Initialize the PyTorch Model (with structural weights)
    model = BiometricLSTM()
    model.eval()
    
    # 2. Create a dummy input tensor that matches the shape of live API data
    # Shape: (batch_size=1, sequence_length=20, features=2)
    dummy_input = torch.randn(1, 20, 2)
    
    # 3. Export to ONNX format
    onnx_path = "models/biometrics_lstm.onnx"
    os.makedirs("models", exist_ok=True)
    
    torch.onnx.export(
        model,                      # The PyTorch model
        dummy_input,                # The mocked tensor to trace the math
        onnx_path,                  # Where to save the compiled C++ graph
        export_params=True,         # Store the trained weights inside the file
        opset_version=14,           # ONNX operation set version
        do_constant_folding=True,   # Optimize by pre-calculating constant math
        input_names=['sequence_input'], 
        output_names=['anomaly_score'],
        dynamic_axes={              # Allow the API to process variable batch sizes
            'sequence_input': {0: 'batch_size'},  
            'anomaly_score': {0: 'batch_size'}
        }
    )
    
    logger.info("✅ Compilation Successful! Optimized ONNX graph saved to: %s", onnx_path)

if __name__ == "__main__":
    compile_lstm_to_onnx()