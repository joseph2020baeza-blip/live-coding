import requests

# Test via Docker Network
base_url = 'http://tienda_backend:5000/api'

login_res = requests.post(f"{base_url}/auth/login", json={"email": "admin@tech.com", "password":"Admin123!"})
login_data = login_res.json()
token = login_data.get('token')
print("Login token:", token)

if token:
    header = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # Let's try what app.js sends exactly.
    # From app.js: const itemsPayload = this.state.cart.map(item => ({ id: item.id }));
    payload = {"items": [{"id": 1}]}
    
    checkout_res = requests.post(f"{base_url}/orders", headers=header, json=payload)
    print("Code:", checkout_res.status_code)
    try:
        print("JSON:", checkout_res.json())
    except:
        print("Text:", checkout_res.text)
