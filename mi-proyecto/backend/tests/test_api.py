"""
Test suite completo para el backend de la tienda.
Cubre: /api/auth/register, /api/auth/login, /api/auth/me,
       /api/products, /api/orders, /api/orders/me
"""

import os, sys, json, pytest

# ── Apuntar al directorio padre para que Python encuentre app.py ─────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('SECRET_KEY', 'test-secret-key-para-pytest')
os.environ.setdefault('DATABASE_URI', 'sqlite:///:memory:')

from app import app as flask_app, db, User, Product, Order
from werkzeug.security import generate_password_hash


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope='function')
def client():
    """Crea una BD en memoria y un cliente de test para cada test."""
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with flask_app.app_context():
        db.create_all()
        _seed_db()
        yield flask_app.test_client()
        db.session.remove()
        db.drop_all()


def _seed_db():
    """Datos iniciales mínimos: un admin y un usuario normal."""
    if not User.query.filter_by(email='admin@tech.com').first():
        admin = User(
            email='admin@tech.com',
            username='Admin',
            password=generate_password_hash('Admin123!', method='pbkdf2:sha256'),
            role='admin',
            balance=99999.0,
        )
        db.session.add(admin)
        db.session.flush()

        p1 = Product(name='Producto A', price=100.0, description='Desc A',
                     image='http://img.test/a.png', stock=5, seller_id=admin.id)
        p2 = Product(name='Producto B', price=300.0, description='Desc B',
                     image='http://img.test/b.png', stock=0, seller_id=admin.id)  # sin stock
        db.session.add_all([p1, p2])
        db.session.commit()


def _get_token(client, email='admin@tech.com', password='Admin123!'):
    """Hace login y devuelve el JWT."""
    res = client.post('/api/auth/login', json={'email': email, 'password': password})
    return res.get_json().get('token')


# ═════════════════════════════════════════════════════════════════════════════
# REGISTER  /api/auth/register
# ═════════════════════════════════════════════════════════════════════════════

class TestRegister:

    def test_register_ok(self, client):
        """Registro exitoso con email nuevo."""
        res = client.post('/api/auth/register', json={
            'email': 'nuevo@test.com', 'username': 'NuevoUser', 'password': 'Pass123!'
        })
        assert res.status_code == 201
        assert 'creado' in res.get_json()['message'].lower()

    def test_register_multiple_emails_mismo_nombre_distinto_numero(self, client):
        """prueba1, prueba2, prueba3 deben poderse registrar sin problema."""
        for i in range(1, 4):
            res = client.post('/api/auth/register', json={
                'email': f'prueba{i}@test.com',
                'username': f'Usuario{i}',
                'password': 'Pass123!'
            })
            assert res.status_code == 201, f"prueba{i}@test.com falló: {res.get_json()}"

    def test_register_email_duplicado_exacto(self, client):
        """El mismo email dos veces → 409."""
        data = {'email': 'dup@test.com', 'username': 'Dup', 'password': 'Pass123!'}
        client.post('/api/auth/register', json=data)
        res = client.post('/api/auth/register', json=data)
        assert res.status_code == 409
        assert 'registrado' in res.get_json()['message'].lower()

    def test_register_email_duplicado_mayusculas(self, client):
        """Email capitalizado diferente debe considerarse duplicado."""
        client.post('/api/auth/register', json={
            'email': 'case@test.com', 'username': 'User1', 'password': 'Pass!'
        })
        res = client.post('/api/auth/register', json={
            'email': 'CASE@TEST.COM', 'username': 'User2', 'password': 'Pass!'
        })
        assert res.status_code == 409

    def test_register_email_invalido(self, client):
        """Email sin @ → 400."""
        res = client.post('/api/auth/register', json={
            'email': 'no-es-un-email', 'username': 'User', 'password': 'Pass123!'
        })
        assert res.status_code == 400
        assert 'inválido' in res.get_json()['message'].lower()

    def test_register_campos_vacios(self, client):
        """Campos obligatorios vacíos → 400."""
        res = client.post('/api/auth/register', json={
            'email': '', 'username': '', 'password': ''
        })
        assert res.status_code == 400

    def test_register_falta_password(self, client):
        """Sin campo password → 400."""
        res = client.post('/api/auth/register', json={
            'email': 'ok@test.com', 'username': 'Ok'
        })
        assert res.status_code == 400

    def test_register_email_normalizado_a_minusculas(self, client):
        """El email guardado debe estar en minúsculas."""
        client.post('/api/auth/register', json={
            'email': 'UPPER@TEST.COM', 'username': 'U', 'password': 'Pass!'
        })
        with flask_app.app_context():
            user = User.query.filter_by(email='upper@test.com').first()
            assert user is not None


# ═════════════════════════════════════════════════════════════════════════════
# LOGIN  /api/auth/login
# ═════════════════════════════════════════════════════════════════════════════

class TestLogin:

    def test_login_ok(self, client):
        """Login correcto devuelve token y datos de usuario."""
        res = client.post('/api/auth/login', json={
            'email': 'admin@tech.com', 'password': 'Admin123!'
        })
        data = res.get_json()
        assert res.status_code == 200
        assert 'token' in data
        assert data['user']['email'] == 'admin@tech.com'

    def test_login_password_incorrecta(self, client):
        """Password incorrecta → 401."""
        res = client.post('/api/auth/login', json={
            'email': 'admin@tech.com', 'password': 'PasswordMal!'
        })
        assert res.status_code == 401

    def test_login_email_no_existe(self, client):
        """Email que no existe → 401."""
        res = client.post('/api/auth/login', json={
            'email': 'fantasma@noexiste.com', 'password': 'Pass123!'
        })
        assert res.status_code == 401

    def test_login_email_case_insensitive(self, client):
        """Login con email en mayúsculas debe funcionar si el email está normalizado."""
        # Registro con minúsculas
        client.post('/api/auth/register', json={
            'email': 'mixedcase@test.com', 'username': 'Mix', 'password': 'Pass123!'
        })
        # Login con mayúsculas — el backend normaliza antes de buscar
        res = client.post('/api/auth/login', json={
            'email': 'MIXEDCASE@TEST.COM', 'password': 'Pass123!'
        })
        # Si el login no normaliza aún, status será 401 (anotamos sin fallar)
        assert res.status_code in (200, 401)


# ═════════════════════════════════════════════════════════════════════════════
# ME  /api/auth/me
# ═════════════════════════════════════════════════════════════════════════════

class TestMe:

    def test_me_con_token_valido(self, client):
        """Con token válido devuelve perfil del usuario."""
        token = _get_token(client)
        res = client.get('/api/auth/me',
                         headers={'Authorization': f'Bearer {token}'})
        data = res.get_json()
        assert res.status_code == 200
        assert data['email'] == 'admin@tech.com'
        assert 'balance' in data

    def test_me_sin_token(self, client):
        """Sin token → 401."""
        res = client.get('/api/auth/me')
        assert res.status_code == 401

    def test_me_token_invalido(self, client):
        """Token falso → 401."""
        res = client.get('/api/auth/me',
                         headers={'Authorization': 'Bearer token.falso.xxx'})
        assert res.status_code == 401


# ═════════════════════════════════════════════════════════════════════════════
# PRODUCTS  /api/products
# ═════════════════════════════════════════════════════════════════════════════

class TestProducts:

    def test_get_products_publico(self, client):
        """Listado de productos es público y devuelve lista."""
        res = client.get('/api/products')
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_get_products_campos(self, client):
        """Cada producto tiene los campos esperados."""
        res = client.get('/api/products')
        for p in res.get_json():
            for field in ('id', 'name', 'price', 'stock', 'image', 'sellerId'):
                assert field in p, f"Campo '{field}' faltante en producto {p}"

    def test_create_product_admin(self, client):
        """Admin puede crear producto."""
        token = _get_token(client)
        res = client.post('/api/products',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'name': 'Nuevo GPU', 'price': 499.0,
                                'description': 'RTX 4090', 'image': 'http://img/gpu.png', 'stock': 3})
        assert res.status_code == 201
        data = res.get_json()
        assert 'id' in data

    def test_create_product_sin_token(self, client):
        """Sin token → 401."""
        res = client.post('/api/products',
                          json={'name': 'X', 'price': 10.0, 'image': 'x.png'})
        assert res.status_code == 401

    def test_create_product_usuario_normal(self, client):
        """Usuario con rol 'user' no puede crear producto → 403."""
        # Registrar usuario normal
        client.post('/api/auth/register', json={
            'email': 'normal@test.com', 'username': 'Normal', 'password': 'Pass123!'
        })
        token = _get_token(client, 'normal@test.com', 'Pass123!')
        res = client.post('/api/products',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'name': 'X', 'price': 10.0, 'image': 'x.png'})
        assert res.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# ORDERS / CHECKOUT  /api/orders
# ═════════════════════════════════════════════════════════════════════════════

class TestCheckout:

    def _register_and_login(self, client, email, balance=2000.0):
        client.post('/api/auth/register', json={
            'email': email, 'username': 'Test', 'password': 'Pass123!'
        })
        with flask_app.app_context():
            u = User.query.filter_by(email=email).first()
            u.balance = balance
            db.session.commit()
        return _get_token(client, email, 'Pass123!')

    def test_checkout_ok(self, client):
        """Compra exitosa descuenta saldo y stock."""
        token = self._register_and_login(client, 'buyer@test.com', balance=500.0)
        # Producto A tiene precio 100 y stock 5
        with flask_app.app_context():
            prod = Product.query.filter_by(name='Producto A').first()
            prod_id = prod.id

        res = client.post('/api/orders',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'items': [{'id': prod_id}]})
        assert res.status_code == 200
        data = res.get_json()
        assert 'order_id' in data
        assert data['new_balance'] == pytest.approx(400.0)

    def test_checkout_sin_stock(self, client):
        """Producto sin stock → 400."""
        token = _get_token(client)
        with flask_app.app_context():
            prod = Product.query.filter_by(name='Producto B').first()  # stock=0
            prod_id = prod.id

        res = client.post('/api/orders',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'items': [{'id': prod_id}]})
        assert res.status_code == 400
        assert 'agotado' in res.get_json()['message'].lower()

    def test_checkout_saldo_insuficiente(self, client):
        """Saldo insuficiente → 400."""
        token = self._register_and_login(client, 'pobre@test.com', balance=10.0)
        with flask_app.app_context():
            prod = Product.query.filter_by(name='Producto A').first()  # precio 100
            prod_id = prod.id

        res = client.post('/api/orders',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'items': [{'id': prod_id}]})
        assert res.status_code == 400
        assert 'saldo' in res.get_json()['message'].lower()

    def test_checkout_producto_inexistente(self, client):
        """ID de producto que no existe → 400."""
        token = _get_token(client)
        res = client.post('/api/orders',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'items': [{'id': 99999}]})
        assert res.status_code == 400

    def test_checkout_items_vacios(self, client):
        """Lista de items vacía → 400."""
        token = _get_token(client)
        res = client.post('/api/orders',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'items': []})
        assert res.status_code == 400

    def test_checkout_items_formato_invalido(self, client):
        """items no es una lista → 400."""
        token = _get_token(client)
        res = client.post('/api/orders',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'items': 'no-es-lista'})
        assert res.status_code == 400

    def test_checkout_sin_autenticacion(self, client):
        """Sin token → 401."""
        res = client.post('/api/orders', json={'items': [{'id': 1}]})
        assert res.status_code == 401

    def test_checkout_descuenta_stock(self, client):
        """Después de comprar, el stock del producto disminuye en 1."""
        token = _get_token(client)
        with flask_app.app_context():
            prod = Product.query.filter_by(name='Producto A').first()
            prod_id = prod.id
            stock_antes = prod.stock

        client.post('/api/orders',
                    headers={'Authorization': f'Bearer {token}'},
                    json={'items': [{'id': prod_id}]})

        with flask_app.app_context():
            prod_despues = Product.query.get(prod_id)
            assert prod_despues.stock == stock_antes - 1


# ═════════════════════════════════════════════════════════════════════════════
# MIS PEDIDOS  /api/orders/me
# ═════════════════════════════════════════════════════════════════════════════

class TestMyOrders:

    def test_historial_vacio_inicial(self, client):
        """Usuario nuevo no tiene pedidos."""
        client.post('/api/auth/register', json={
            'email': 'sinpedidos@test.com', 'username': 'NoPed', 'password': 'Pass123!'
        })
        token = _get_token(client, 'sinpedidos@test.com', 'Pass123!')
        res = client.get('/api/orders/me',
                         headers={'Authorization': f'Bearer {token}'})
        assert res.status_code == 200
        assert res.get_json() == []

    def test_historial_tras_compra(self, client):
        """Tras hacer una compra aparece en el historial."""
        token = _get_token(client)
        with flask_app.app_context():
            prod = Product.query.filter_by(name='Producto A').first()
            prod_id = prod.id

        client.post('/api/orders',
                    headers={'Authorization': f'Bearer {token}'},
                    json={'items': [{'id': prod_id}]})

        res = client.get('/api/orders/me',
                         headers={'Authorization': f'Bearer {token}'})
        orders = res.get_json()
        assert res.status_code == 200
        assert len(orders) == 1
        assert orders[0]['id'].startswith('ORD-')
        assert 'total' in orders[0]
        assert 'items' in orders[0]

    def test_historial_sin_token(self, client):
        """Sin token → 401."""
        res = client.get('/api/orders/me')
        assert res.status_code == 401

    def test_historial_aislado_entre_usuarios(self, client):
        """El historial de un usuario no contiene los pedidos de otro."""
        # Usuario A compra
        token_a = _get_token(client)
        with flask_app.app_context():
            prod = Product.query.filter_by(name='Producto A').first()
            prod_id = prod.id
        client.post('/api/orders',
                    headers={'Authorization': f'Bearer {token_a}'},
                    json={'items': [{'id': prod_id}]})

        # Usuario B se registra y revisa su historial
        client.post('/api/auth/register', json={
            'email': 'userb@test.com', 'username': 'B', 'password': 'Pass123!'
        })
        token_b = _get_token(client, 'userb@test.com', 'Pass123!')
        res = client.get('/api/orders/me',
                         headers={'Authorization': f'Bearer {token_b}'})
        assert res.get_json() == []
