import pytest
import requests
import time
import os
import subprocess

# @pytest.fixture(scope="session", autouse=True)
# def start_docker_container():
#     # Check if the container is already running
#     container_id = os.popen("docker ps -q -f name=conformance_test").read().strip()
#     if not container_id:  # Start only if not running
#         docker_image = os.environ.get('DOCKER_IMAGE', 'conformance_test_environment')
#         command = f"docker run -d -p 5000:5000 --name conformance_test {docker_image}"
#         subprocess.run(command, shell=True, check=True)  # Use subprocess for better error handling
#         time.sleep(5)  # Give the container time to start

#     yield  # This is where the tests run

#     # Teardown: Stop the container after all tests have finished (for CI)
#     subprocess.run("docker stop conformance_test", shell=True, check=True)
#     subprocess.run("docker rm conformance_test", shell=True, check=True)


def test_valid_token_refresh():
    url = "http://localhost:5007/oauth2/token200"
    data = {
        'grant_type': 'refresh_token',
        'client_id': 'conformance_client',
        'client_secret': 'conformance_client_secret',
        'refresh_token': 'mock_refresh_token'
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json()['access_token'] == 'mock_access_token'
    assert response.json()['token_type'] == 'bearer'
    assert response.json()['refresh_token'] == 'mock_refresh_token'




