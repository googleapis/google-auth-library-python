#!/bin/bash

set -euo pipefail

# Docker image to pull (your test "server" image)
readonly TEST_IMAGE="gcr.io/client-debugging/conformance_test_environment_0:conformance_test_environment_v2"

# Project root
readonly PROJECT_ROOT="$(git rev-parse --show-toplevel)"

# Test directory at the project root
readonly TEST_DIR="conformance-tests"

# Check if the test directory exists
if [[ ! -d "${PROJECT_ROOT}/${TEST_DIR}" ]]; then
    echo "ERROR: Test directory '${TEST_DIR}' not found. Aborting." >&2
    exit 1
fi

docker pull "${TEST_IMAGE}" || {  # Pull the docker image. Exit if it fails.
    echo "ERROR: Failed to pull Docker image. Aborting." >&2
    exit 1
}


# Start the Docker container (detached mode, expose port)
PORT=5007  # Set the desired port here
container_id=$(docker run -d -p "${PORT}":5000 "${TEST_IMAGE}") || { 
    echo "ERROR: Failed to start Docker container. Aborting." >&2
    exit 1
}

cleanup() { # Define the cleanup function
    docker stop "${container_id}" || true  # Stop; ignore errors if already stopped
    docker rm "${container_id}" || true  # Remove; ignore errors if already removed
}

trap cleanup EXIT  # Ensure cleanup on ANY exit (normal or error)

# Wait for the container's port to be open (adjust timeout as needed)
for i in {1..30}; do  # Try for 30 seconds
    if docker exec "${container_id}" bash -c 'nc -z localhost 5000'; then
        echo "Container port 5000 is open. Proceeding with tests..."
        break  # Port is open, exit the loop
    fi
    sleep 1
done


if [[ $i -eq 30 ]]; then # timeout reached
    echo "ERROR: Timeout waiting for container port 5000 to open. Aborting." >&2
    docker stop "${container_id}"  # Stop the container on error
    docker rm "${container_id}"
    exit 1
fi


# Run your tests (outside the container, against localhost:5000)
python3 -m pip install --user pytest  # Install pytest if needed
cd "${PROJECT_ROOT}/${TEST_DIR}"
PORT="${PORT}" python3 -m pytest  user_tests.py  # Or any other test runner

# Capture the exit code of the test run
exit_code=$?

# Stop and remove the container
docker stop "${container_id}"
docker rm "${container_id}"

exit "${exit_code}"
