Write-Host "`n[1/3] Running black..."
black --check .

Write-Host "`n[2/3] Running ruff..."
ruff .

Write-Host "`n[3/3] Running pytest for Phase 1..."
pytest tests/test_identity_pool.py
