"""
Script de smoke-test manual contra el backend via red Docker.
Uso: ejecutar desde dentro del contenedor frontend o desde la red interna.

URL configurable mediante variable de entorno:
    export BASE_URL=https://tudominio.com/api  # producción (HTTPS)
    export BASE_URL=http://tienda_backend:5000/api  # red Docker interna

Si no se define BASE_URL, se usa http://tienda_backend:5000/api como fallback
(solo para la red Docker interna donde HTTP es aceptable — el tráfico no sale
a internet y está confinado a la bridge network privada de Docker Compose).
"""
import os
import requests

# ── Configuración ─────────────────────────────────────────────────────────────
# B105-SAFE: La URL base se lee de una variable de entorno.
# Para producción con TLS: export BASE_URL=https://<host>/api
BASE_URL = os.getenv('BASE_URL', 'http://tienda_backend:5000/api')

TIMEOUT = 10  # segundos — evita que el test se quede colgado (B113)

# ── Login ─────────────────────────────────────────────────────────────────────
login_res = requests.post(
    f"{BASE_URL}/auth/login",
    json={"email": "admin@tech.com", "password": os.getenv('TEST_ADMIN_PASSWORD', 'Admin123!')},
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
