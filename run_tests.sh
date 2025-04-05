#!/bin/bash
set -e

echo -e "\n🔍 [1/3] Running black..."
black --check rewired tests/test_identity_pool.py

echo -e "\n🧼 [2/3] Running ruff..."
ruff check rewired tests/test_identity_pool.py

echo -e "\n🧪 [3/3] Running pytest for Phase 1..."
pytest tests/test_identity_pool.py
