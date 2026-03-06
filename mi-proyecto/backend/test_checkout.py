import requests
import json

base_url = 'http://localhost:5000/api'

# Login
login_res = requests.post(f"{base_url}/auth/login", json={"email": "admin@tech.com", "password":"Admin123!"})
login_data = login_res.json()
print("Login:", login_data)
token = login_data.get('token')

if token:
    # TryCheckout
    header = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"items": [{"id": 1}]}
    checkout_res = requests.post(f"{base_url}/orders", headers=header, json=payload)
    print("Checkout status:", checkout_res.status_code)
    try:
        print("Checkout response:", checkout_res.json())
    except:
        print("Checkout raw:", checkout_res.text)
