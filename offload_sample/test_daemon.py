import requests
res = requests.post('http://localhost:5000/sign', json={"mytext":"lalala"})
if res.ok:
    print(res.json())