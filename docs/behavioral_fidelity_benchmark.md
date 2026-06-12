
# Behavioral Fidelity Benchmark

This benchmark evaluates whether synthetic mule transaction graphs preserve important fraud behaviour patterns.

## Features

- Burst transaction detection
- Fan-in / fan-out motif analysis
- Circular transaction flow detection
- Transaction velocity analysis
- Centrality concentration analysis

## Expected Input Columns

source_account
target_account
amount
timestamp

## Usage

Call `benchmark_behavioral_fidelity()` with a pandas DataFrame containing transaction records.

The function returns a dictionary of fidelity metrics along with an overall behavioural fidelity score.
