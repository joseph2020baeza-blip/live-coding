"""
Script de smoke-test manual contra el backend via red Docker.
Uso: ejecutar desde dentro del contenedor frontend o desde la red interna.
Requiere: backend accesible en http://tienda_backend:5000
"""
import requests

BASE_URL = 'http://tienda_backend:5000/api'
TIMEOUT = 10  # segundos — evita que el test se quede colgado indefinidamente (B113)

# ── Login ────────────────────────────────────────────────────────────────────
login_res = requests.post(
    f"{BASE_URL}/auth/login",
    json={"email": "admin@tech.com", "password": "Admin123!"},
    timeout=TIMEOUT
)
login_data = login_res.json()
token = login_data.get('token')
print("Login token:", token)

if token:
    header = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    # Replica el payload que envía app.js:
    # const itemsPayload = this.state.cart.map(item => ({ id: item.id }));
    payload = {"items": [{"id": 1}]}

    # ── Checkout via Nginx ────────────────────────────────────────────────────
    checkout_res = requests.post(
        f"{BASE_URL}/orders",
        headers=header,
        json=payload,
        timeout=TIMEOUT
    )
    print("Code:", checkout_res.status_code)
    try:
        print("JSON:", checkout_res.json())
    except requests.exceptions.JSONDecodeError:
        print("Text:", checkout_res.text)
else:
    print("ERROR: No se obtuvo token. Verifica la red Docker y el estado del backend.")
