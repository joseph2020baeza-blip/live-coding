"""
Script de smoke-test manual contra el backend en ejecución.
Uso: python test_checkout.py
Requiere: servidor corriendo en http://localhost:5000
"""
import requests
import json

BASE_URL = 'http://localhost:5000/api'
TIMEOUT = 10  # segundos — evita que el test se quede colgado indefinidamente (B113)

# ── Login ────────────────────────────────────────────────────────────────────
login_res = requests.post(
    f"{BASE_URL}/auth/login",
    json={"email": "admin@tech.com", "password": "Admin123!"},
    timeout=TIMEOUT
)
login_data = login_res.json()
print("Login status:", login_res.status_code)
print("Login data:", login_data)
token = login_data.get('token')

if token:
    header = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {"items": [{"id": 1}]}

    # ── Checkout ─────────────────────────────────────────────────────────────
    checkout_res = requests.post(
        f"{BASE_URL}/orders",
        headers=header,
        json=payload,
        timeout=TIMEOUT
    )
    print("Checkout status:", checkout_res.status_code)
    try:
        print("Checkout response:", checkout_res.json())
    except requests.exceptions.JSONDecodeError:
        print("Checkout raw:", checkout_res.text)
else:
    print("ERROR: No se obtuvo token. Verifica que el servidor esté corriendo.")
