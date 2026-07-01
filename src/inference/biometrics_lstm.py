import os
import numpy as np
import torch
import torch.nn as nn
import logging

logger = logging.getLogger(__name__)

class BiometricLSTM(nn.Module):
    """
    Long Short-Term Memory architecture for sequential keystroke analysis.
    Learns temporal dependencies in typing cadence to detect anomalies.
    """
    def __init__(self, input_size=2, hidden_size=32, num_layers=2):
        super().__init__()
        # Input features: [flight_time, hold_time] per keystroke
        self.lstm = nn.LSTM(
            input_size=input_size, 
            hidden_size=hidden_size, 
            num_layers=num_layers, 
            batch_first=True, 
            dropout=0.2
        )
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # x shape: (batch_size, sequence_length, features)
        _, (hn, _) = self.lstm(x)
        # Extract the hidden state of the final LSTM layer
        out = self.fc(hn[-1])
        # Output a probability between 0.0 (Normal) and 1.0 (Anomaly/Bot)
        return self.sigmoid(out).squeeze(-1)


class KeystrokeSequenceAnalyzer:
    """
    Wrapper class to handle data normalization, model loading, 
    and fallback logic for the production API.
    """
    def __init__(self, model_path="models/biometrics_lstm.pt"):
        self.model_path = model_path
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = BiometricLSTM().to(self.device)
        self.is_loaded = False

        if os.path.exists(self.model_path):
            try:
                self.model.load_state_dict(torch.load(self.model_path, map_location=self.device, weights_only=True))
                self.model.eval()
                self.is_loaded = True
                logger.info("Biometric LSTM: Weights loaded successfully on %s.", self.device)
            except Exception as e:
                logger.warning("Warning: Failed to load Biometric LSTM weights: %s", e)
        else:
            logger.warning("Biometric LSTM: Weights not found. Utilizing static mathematical fallback.")

    def analyze_sequence(self, flight_times, hold_times):
        """
        Evaluates the keystroke array. Returns a stress/bot probability (0.0 to 1.0).
        """
        # Ensure we have enough keystrokes to form a meaningful sequence
        if len(flight_times) < 5 or len(hold_times) < 5:
            return 0.0

        if self.is_loaded:
            # --- DEEP LEARNING INFERENCE PATH ---
            # Standardize sequence length (truncate or pad to 20 keystrokes)
            seq_len = 20
            ft = (flight_times[:seq_len] + [0.0]*seq_len)[:seq_len]
            ht = (hold_times[:seq_len] + [0.0]*seq_len)[:seq_len]

            # Normalize data to prevent gradient explosion in the LSTM
            ft = (np.array(ft) - np.mean(ft)) / (np.std(ft) + 1e-6)
            ht = (np.array(ht) - np.mean(ht)) / (np.std(ht) + 1e-6)

            # Reshape for PyTorch: (batch=1, seq_len=20, features=2)
            tensor_input = torch.tensor(
                np.column_stack((ft, ht)), dtype=torch.float32
            ).unsqueeze(0).to(self.device)

            with torch.no_grad():
                anomaly_prob = self.model(tensor_input).item()
            return anomaly_prob
            
        else:
            # --- STATIC MATH FALLBACK PATH (Legacy API Logic) ---
            flight_cv = np.std(flight_times) / (np.mean(flight_times) + 1e-6)
            if flight_cv > 0.30:
                return 0.85  # High probability of anomaly (High CoV)
            return 0.10


if __name__ == "__main__":
    # Local verification block
    print("--- Testing Keystroke Sequence Analyzer ---")
    analyzer = KeystrokeSequenceAnalyzer()
    
    # Mock some keystroke data (simulating a bot typing with perfect 100ms intervals)
    mock_flight = [100.0, 100.0, 100.1, 99.9, 100.0, 100.0]
    mock_hold = [45.0, 45.0, 45.5, 44.9, 45.0, 45.0]
    
    score = analyzer.analyze_sequence(mock_flight, mock_hold)
    print(f"Anomaly Score Output: {score:.4f}")