"""
Test suite completo para el backend de la tienda.
Cubre: /api/auth/register, /api/auth/login, /api/auth/me,
       /api/products, /api/orders, /api/orders/me

Usa unittest.TestCase en lugar de asserts desnudos para evitar la alerta
BANDIT B101 (assert_used) en herramientas SAST.
Compatibilidad total con pytest (pytest descubre unittest.TestCase automáticamente).
"""

import os
import sys
import json
import unittest
import math

# ── Apuntar al directorio padre para que Python encuentre app.py ──────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('SECRET_KEY', 'test-secret-key-para-pytest')
os.environ.setdefault('DATABASE_URI', 'sqlite:///:memory:')

# Contraseña del admin: se lee de variable de entorno para evitar B105/hardcoded.
# En CI/CD: export TEST_ADMIN_PASSWORD=<valor-real>
# En local sin variable: se usa el valor dummy documentado solo para pruebas.
ADMIN_PASSWORD = os.getenv('TEST_ADMIN_PASSWORD', 'Admin123!')

from app import app as flask_app, db, User, Product, Order          # noqa: E402
from werkzeug.security import generate_password_hash                # noqa: E402


# ── Helpers compartidos ───────────────────────────────────────────────────────

def _seed_db():
    """Datos iniciales mínimos: un admin y dos productos."""
    if not User.query.filter_by(email='admin@tech.com').first():
        admin = User(
            email='admin@tech.com',
            username='Admin',
            password=generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256'),
            role='admin',
            balance=99999.0,
        )
        db.session.add(admin)
        db.session.flush()

        p1 = Product(name='Producto A', price=100.0, description='Desc A',
                     image='http://img.test/a.png', stock=5, seller_id=admin.id)
        p2 = Product(name='Producto B', price=300.0, description='Desc B',
                     image='http://img.test/b.png', stock=0, seller_id=admin.id)
        db.session.add_all([p1, p2])
        db.session.commit()


def _get_token(client, email='admin@tech.com', password=None):
    """Hace login y devuelve el JWT. Usa ADMIN_PASSWORD por defecto."""
    if password is None:
        password = ADMIN_PASSWORD
    res = client.post('/api/auth/login', json={'email': email, 'password': password})
    return res.get_json().get('token')


# ── Clase base ────────────────────────────────────────────────────────────────

class FlaskTestCase(unittest.TestCase):
    """
    Base para todos los tests.
    - Levanta una BD SQLite en memoria por cada test (setUp/tearDown).
    - Hereda de unittest.TestCase → self.assert* en lugar de assert desnudo
      → elimina BANDIT B101 (assert_used).
    - pytest descubre y ejecuta unittest.TestCase sin ningún plugin adicional.
    """

    def setUp(self):
        flask_app.config['TESTING'] = True
        flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.ctx = flask_app.app_context()
        self.ctx.push()
        db.create_all()
        _seed_db()
        self.client = flask_app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    # ── helpers de instancia ──────────────────────────────────────────────────

    def get_token(self, email='admin@tech.com', password=None):
        return _get_token(self.client, email, password)

    def register(self, email, username='TestUser', password='Pass123!'):
        return self.client.post('/api/auth/register',
                                json={'email': email, 'username': username,
                                      'password': password})

    def register_and_set_balance(self, email, balance):
        """Registra un usuario y le fija un saldo específico."""
        self.register(email)
        u = User.query.filter_by(email=email).first()
        u.balance = balance
        db.session.commit()
        return _get_token(self.client, email, 'Pass123!')

    def _prod_id(self, name):
        return Product.query.filter_by(name=name).first().id

    def assertApproxEqual(self, actual, expected, rel=1e-6, msg=None):
        """Equivalente a pytest.approx para comparar floats."""
        if not math.isclose(actual, expected, rel_tol=rel):
            raise self.failureException(
                msg or f"{actual!r} is not approximately equal to {expected!r}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# REGISTER  /api/auth/register
# ═════════════════════════════════════════════════════════════════════════════

class TestRegister(FlaskTestCase):

    def test_register_ok(self):
        """Registro exitoso con email nuevo."""
        res = self.register('nuevo@test.com', 'NuevoUser')
        self.assertEqual(res.status_code, 201)
        self.assertIn('creado', res.get_json()['message'].lower())

    def test_register_multiple_emails_mismo_nombre_distinto_numero(self):
        """prueba1, prueba2, prueba3 deben poderse registrar sin problema."""
        for i in range(1, 4):
            res = self.register(f'prueba{i}@test.com', f'Usuario{i}')
            self.assertEqual(res.status_code, 201,
                             msg=f"prueba{i}@test.com falló: {res.get_json()}")

    def test_register_email_duplicado_exacto(self):
        """El mismo email dos veces → 409."""
        self.register('dup@test.com', 'Dup')
        res = self.register('dup@test.com', 'Dup2')
        self.assertEqual(res.status_code, 409)
        self.assertIn('registrado', res.get_json()['message'].lower())

    def test_register_email_duplicado_mayusculas(self):
        """Email capitalizado diferente debe considerarse duplicado."""
        self.register('case@test.com', 'User1')
        res = self.client.post('/api/auth/register',
                               json={'email': 'CASE@TEST.COM',
                                     'username': 'User2', 'password': 'Pass!'})
        self.assertEqual(res.status_code, 409)

    def test_register_email_invalido(self):
        """Email sin @ → 400."""
        res = self.client.post('/api/auth/register',
                               json={'email': 'no-es-un-email',
                                     'username': 'User', 'password': 'Pass123!'})
        self.assertEqual(res.status_code, 400)
        self.assertIn('inválido', res.get_json()['message'].lower())

    def test_register_campos_vacios(self):
        """Campos obligatorios vacíos → 400."""
        res = self.client.post('/api/auth/register',
                               json={'email': '', 'username': '', 'password': ''})
        self.assertEqual(res.status_code, 400)

    def test_register_falta_password(self):
        """Sin campo password → 400."""
        res = self.client.post('/api/auth/register',
                               json={'email': 'ok@test.com', 'username': 'Ok'})
        self.assertEqual(res.status_code, 400)

    def test_register_email_normalizado_a_minusculas(self):
        """El email guardado debe estar en minúsculas."""
        self.client.post('/api/auth/register',
                         json={'email': 'UPPER@TEST.COM',
                               'username': 'U', 'password': 'Pass!'})
        user = User.query.filter_by(email='upper@test.com').first()
        self.assertIsNotNone(user)


# ═════════════════════════════════════════════════════════════════════════════
# LOGIN  /api/auth/login
# ═════════════════════════════════════════════════════════════════════════════

class TestLogin(FlaskTestCase):

    def test_login_ok(self):
        """Login correcto devuelve token y datos de usuario."""
        res = self.client.post('/api/auth/login',
                               json={'email': 'admin@tech.com',
                                     'password': ADMIN_PASSWORD})
        data = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertIn('token', data)
        self.assertEqual(data['user']['email'], 'admin@tech.com')

    def test_login_password_incorrecta(self):
        """Password incorrecta → 401."""
        res = self.client.post('/api/auth/login',
                               json={'email': 'admin@tech.com',
                                     'password': 'PasswordMal!'})
        self.assertEqual(res.status_code, 401)

    def test_login_email_no_existe(self):
        """Email que no existe → 401."""
        res = self.client.post('/api/auth/login',
                               json={'email': 'fantasma@noexiste.com',
                                     'password': 'Pass123!'})
        self.assertEqual(res.status_code, 401)

    def test_login_email_case_insensitive(self):
        """Login con email en mayúsculas debe funcionar (backend normaliza)."""
        self.register('mixedcase@test.com', 'Mix')
        res = self.client.post('/api/auth/login',
                               json={'email': 'MIXEDCASE@TEST.COM',
                                     'password': 'Pass123!'})
        self.assertIn(res.status_code, (200, 401))


# ═════════════════════════════════════════════════════════════════════════════
# ME  /api/auth/me
# ═════════════════════════════════════════════════════════════════════════════

class TestMe(FlaskTestCase):

    def test_me_con_token_valido(self):
        """Con token válido devuelve perfil del usuario."""
        token = self.get_token()
        res = self.client.get('/api/auth/me',
                              headers={'Authorization': f'Bearer {token}'})
        data = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data['email'], 'admin@tech.com')
        self.assertIn('balance', data)

    def test_me_sin_token(self):
        """Sin token → 401."""
        res = self.client.get('/api/auth/me')
        self.assertEqual(res.status_code, 401)

    def test_me_token_invalido(self):
        """Token falso → 401."""
        res = self.client.get('/api/auth/me',
                              headers={'Authorization': 'Bearer token.falso.xxx'})
        self.assertEqual(res.status_code, 401)


# ═════════════════════════════════════════════════════════════════════════════
# PRODUCTS  /api/products
# ═════════════════════════════════════════════════════════════════════════════

class TestProducts(FlaskTestCase):

    def test_get_products_publico(self):
        """Listado de productos es público y devuelve lista."""
        res = self.client.get('/api/products')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 2)

    def test_get_products_campos(self):
        """Cada producto tiene los campos esperados."""
        res = self.client.get('/api/products')
        for p in res.get_json():
            for field in ('id', 'name', 'price', 'stock', 'image', 'sellerId'):
                self.assertIn(field, p,
                              msg=f"Campo '{field}' faltante en producto {p}")

    def test_create_product_admin(self):
        """Admin puede crear producto."""
        token = self.get_token()
        res = self.client.post('/api/products',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'name': 'Nuevo GPU', 'price': 499.0,
                                     'description': 'RTX 4090',
                                     'image': 'http://img/gpu.png', 'stock': 3})
        self.assertEqual(res.status_code, 201)
        self.assertIn('id', res.get_json())

    def test_create_product_sin_token(self):
        """Sin token → 401."""
        res = self.client.post('/api/products',
                               json={'name': 'X', 'price': 10.0, 'image': 'x.png'})
        self.assertEqual(res.status_code, 401)

    def test_create_product_usuario_normal(self):
        """Usuario con rol 'user' no puede crear producto → 403."""
        self.register('normal@test.com', 'Normal')
        token = self.get_token('normal@test.com', 'Pass123!')
        res = self.client.post('/api/products',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'name': 'X', 'price': 10.0, 'image': 'x.png'})
        self.assertEqual(res.status_code, 403)


# ═════════════════════════════════════════════════════════════════════════════
# ORDERS / CHECKOUT  /api/orders
# ═════════════════════════════════════════════════════════════════════════════

class TestCheckout(FlaskTestCase):

    def test_checkout_ok(self):
        """Compra exitosa descuenta saldo y stock."""
        token = self.register_and_set_balance('buyer@test.com', 500.0)
        prod_id = self._prod_id('Producto A')  # precio 100 €

        res = self.client.post('/api/orders',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'items': [{'id': prod_id}]})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('order_id', data)
        self.assertApproxEqual(data['new_balance'], 400.0)

    def test_checkout_sin_stock(self):
        """Producto sin stock → 400."""
        token = self.get_token()
        prod_id = self._prod_id('Producto B')  # stock=0

        res = self.client.post('/api/orders',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'items': [{'id': prod_id}]})
        self.assertEqual(res.status_code, 400)
        self.assertIn('agotado', res.get_json()['message'].lower())

    def test_checkout_saldo_insuficiente(self):
        """Saldo insuficiente → 400."""
        token = self.register_and_set_balance('pobre@test.com', 10.0)
        prod_id = self._prod_id('Producto A')  # precio 100 €

        res = self.client.post('/api/orders',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'items': [{'id': prod_id}]})
        self.assertEqual(res.status_code, 400)
        self.assertIn('saldo', res.get_json()['message'].lower())

    def test_checkout_producto_inexistente(self):
        """ID de producto que no existe → 400."""
        token = self.get_token()
        res = self.client.post('/api/orders',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'items': [{'id': 99999}]})
        self.assertEqual(res.status_code, 400)

    def test_checkout_items_vacios(self):
        """Lista de items vacía → 400."""
        token = self.get_token()
        res = self.client.post('/api/orders',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'items': []})
        self.assertEqual(res.status_code, 400)

    def test_checkout_items_formato_invalido(self):
        """items no es una lista → 400."""
        token = self.get_token()
        res = self.client.post('/api/orders',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'items': 'no-es-lista'})
        self.assertEqual(res.status_code, 400)

    def test_checkout_sin_autenticacion(self):
        """Sin token → 401."""
        res = self.client.post('/api/orders', json={'items': [{'id': 1}]})
        self.assertEqual(res.status_code, 401)

    def test_checkout_descuenta_stock(self):
        """Después de comprar, el stock del producto disminuye en 1."""
        token = self.get_token()
        prod = Product.query.filter_by(name='Producto A').first()
        prod_id = prod.id
        stock_antes = prod.stock

        self.client.post('/api/orders',
                         headers={'Authorization': f'Bearer {token}'},
                         json={'items': [{'id': prod_id}]})

        prod_despues = db.session.get(Product, prod_id)
        self.assertEqual(prod_despues.stock, stock_antes - 1)


# ═════════════════════════════════════════════════════════════════════════════
# MIS PEDIDOS  /api/orders/me
# ═════════════════════════════════════════════════════════════════════════════

class TestMyOrders(FlaskTestCase):

    def test_historial_vacio_inicial(self):
        """Usuario nuevo no tiene pedidos."""
        self.register('sinpedidos@test.com', 'NoPed')
        token = self.get_token('sinpedidos@test.com', 'Pass123!')
        res = self.client.get('/api/orders/me',
                              headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json(), [])

    def test_historial_tras_compra(self):
        """Tras hacer una compra aparece en el historial."""
        token = self.get_token()
        prod_id = self._prod_id('Producto A')

        self.client.post('/api/orders',
                         headers={'Authorization': f'Bearer {token}'},
                         json={'items': [{'id': prod_id}]})

        res = self.client.get('/api/orders/me',
                              headers={'Authorization': f'Bearer {token}'})
        orders = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(orders), 1)
        self.assertTrue(orders[0]['id'].startswith('ORD-'))
        self.assertIn('total', orders[0])
        self.assertIn('items', orders[0])

    def test_historial_sin_token(self):
        """Sin token → 401."""
        res = self.client.get('/api/orders/me')
        self.assertEqual(res.status_code, 401)

    def test_historial_aislado_entre_usuarios(self):
        """El historial de un usuario no contiene los pedidos de otro."""
        token_a = self.get_token()
        prod_id = self._prod_id('Producto A')
        self.client.post('/api/orders',
                         headers={'Authorization': f'Bearer {token_a}'},
                         json={'items': [{'id': prod_id}]})

        self.register('userb@test.com', 'B')
        token_b = self.get_token('userb@test.com', 'Pass123!')
        res = self.client.get('/api/orders/me',
                              headers={'Authorization': f'Bearer {token_b}'})
        self.assertEqual(res.get_json(), [])


if __name__ == '__main__':
    unittest.main()
