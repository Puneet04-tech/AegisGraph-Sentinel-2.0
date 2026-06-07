# TODO

## Step 1: CI workflow failure
- [ ] Inspect `.github/workflows/ci.yml`
- [ ] Patch to satisfy `tests/test_ci_workflow.py` exact string assertions

## Step 2: `.env.example` docs failure
- [ ] Check if `.env.example` exists at repo root
- [ ] Create/update `.env.example` so it includes all required variables and instruction text

## Step 3: Exception logging failure
- [ ] Run failing test(s) for `tests/test_exception_logging.py::TestApiIntegration::test_http_exception_standardized_json`
- [ ] Inspect `/api/v1/explain` error path in `src/api/main.py` and handlers/payload builders
- [ ] Fix error payload/headers to match assertions

## Step 4: Explainer deferral failure
- [ ] Run failing test(s) for `tests/test_explainer.py::test_aegis_model_explainer_defers_gnn_explainer_construction`
- [ ] Inspect `src/inference/explainer.py` and ensure GNNExplainer is not constructed until first `extract_critical_topology` call

## Step 5: LRU prune failure
- [ ] Run failing test(s) for `tests/test_lateral_movement_lru.py::test_update_graph_prunes_least_recently_used_nodes`
- [ ] Fix `_prune_lru_nodes` / access-order tracking to match expected behavior

## Step 6: Model/provider/scorer failures
- [ ] Run `tests/test_models.py` failing cases and patch `src/models/*` for correct shapes/outputs
- [ ] Run `tests/test_neo4j_provider.py` failing cases and patch provider integration
- [ ] Run `tests/test_production_scorer.py` failing cases and patch scorer chunking logic

## Step 7: Re-run full suite
- [ ] `pytest -q` and confirm all tests pass

