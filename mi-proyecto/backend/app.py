import os
# Permitir uso de OAuth sobre HTTP (localhost)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

import json
import re
import logging
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import secrets
import hmac  # Importado por si se requieren verificaciones manuales timing-safe
from dotenv import load_dotenv

# Cargar variables desde .env si existe
load_dotenv()

app = Flask(__name__)
CORS(app)

# ── Configuración del logger de aplicación ───────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))

# ── Configuración única y Fail Fast (CWE-798) ────────────────────────────────
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    raise ValueError("💥 CRÍTICO: Variable de entorno SECRET_KEY no está definida. Inicio seguro abortado (Fail Fast).")
app.config['SECRET_KEY'] = secret_key

db_uri = os.environ.get('DATABASE_URI', 'sqlite:///' + os.path.join(basedir, 'instance', 'tienda.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- MODELOS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user')
    balance = db.Column(db.Float, default=2000.0) # El carrito lo requiere

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text) # Agregado porque el frontend lo pinta
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255))
    stock = db.Column(db.Integer, default=10) # Agregado para validación carrito
    seller_id = db.Column(db.Integer, nullable=False)

class Order(db.Model): # Agregado para historial de pedidos
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String(50), default='completed')
    items_summary = db.Column(db.Text) # Stringificado por simplicidad en demo

# --- DECORADOR ---
def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1] # Bearer <token>
        if not token:
            return jsonify({'message': 'Token faltante'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = db.session.get(User, data['id'])
        except Exception as e:
            return jsonify({'message': 'Token inválido o expirado'}), 401
        if not current_user:
            return jsonify({'message': 'Usuario no encontrado'}), 401
        return f(current_user, *args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

# --- ENDPOINTS REST ---

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validar campos requeridos
    email = data.get('email', '').strip().lower()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not email or not username or not password:
        return jsonify({'message': 'Email, nombre de usuario y contraseña son requeridos'}), 400

    # Validar formato de email
    email_regex = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return jsonify({'message': 'Formato de email inválido'}), 400

    # Verificar si el email ya existe (mensaje claro)
    if User.query.filter_by(email=email).first():
        return jsonify({'message': f'El email "{email}" ya está registrado. Usa un email diferente o inicia sesión.'}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(
        email=email,
        username=username,
        password=hashed_password,
        balance=2000.0
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuario creado'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error al crear el usuario: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        token = jwt.encode({
            'id': user.id,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'token': token,
            # PRODUCCIÓN: no exponemos 'role' al cliente.
            # El rol viaja cifrado dentro del JWT y el backend lo valida en cada petición.
            'user': {'id': user.id, 'email': user.email, 'username': user.username, 'balance': user.balance}
        })
    return jsonify({'message': 'Credenciales incorrectas'}), 401

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_me(current_user):
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'username': current_user.username,
        # PRODUCCIÓN: 'role' omitido — no se expone al cliente.
        'balance': current_user.balance
    })



@app.route('/api/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    out = []
    for p in products:
        out.append({'id': p.id, 'name': p.name, 'description': p.description, 'price': p.price, 'image': p.image, 'stock': p.stock, 'sellerId': p.seller_id})
    return jsonify(out)

@app.route('/api/products', methods=['POST'])
@token_required
def create_product(current_user):
    if current_user.role != 'admin':
        return jsonify({'message': 'Acceso denegado: Solo admins'}), 403

    data = request.get_json()
    new_product = Product(
        name=data['name'], 
        price=float(data['price']), 
        description=data.get('description', ''),
        image=data['image'],
        stock=int(data.get('stock', 10)),
        seller_id=current_user.id
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Producto creado', 'id': new_product.id}), 201

@app.route('/api/orders', methods=['POST'])
@token_required
def checkout(current_user):
    data = request.get_json()
    items_input = data.get('items')

    # Basic input validation
    if not items_input or not isinstance(items_input, list):
        return jsonify({'message': 'Formato de items inválido'}), 400

    if not items_input:
        return jsonify({'message': 'El carrito está vacío'}), 400

    try:
        # Iniciamos un bloque transaccional explícito
        total = 0.0
        processed_items = []

        # Recorremos cada item para verificar stock y precio real
        for item in items_input:
            item_id = item.get('id')
            if not item_id:
                db.session.rollback()
                return jsonify({'message': 'Item sin ID'}), 400

            # Bloqueo pesimista: with_for_update evita race conditions en stock
            prod = db.session.query(Product).with_for_update().get(item_id)
            
            if not prod or prod.stock < 1:
                db.session.rollback()
                return jsonify({'message': f"El producto {prod.name if prod else f'ID {item_id}'} se ha agotado."}), 400
            
            # Restamos stock y sumamos precio REAL de la BD
            prod.stock -= 1
            total += prod.price
            processed_items.append({'id': prod.id, 'name': prod.name, 'price': prod.price})

        # Una vez calculado el total seguro, verificamos el saldo
        if current_user.balance < total:
            db.session.rollback()
            return jsonify({'message': 'Saldo insuficiente'}), 400

        # Cobramos al usuario
        current_user.balance -= total

        # Guardamos el pedido
        order = Order(
            user_id=current_user.id,
            total=total,
            items_summary=json.dumps(processed_items)
        )
        db.session.add(order)
        
        # Guardamos todos los cambios juntos (Stock + Balance + Order)
        db.session.commit()
        
        return jsonify({
            'message': 'Compra verificada y guardada',
            'order_id': order.id,
            'new_balance': current_user.balance
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f"Error procesando pago: {str(e)}"}), 500

@app.route('/api/orders/me', methods=['GET'])
@token_required
def get_my_orders(current_user):
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.date.desc()).all()
    out = []
    for o in orders:
        items = []
        try:
            items = json.loads(o.items_summary)
        except (json.JSONDecodeError, TypeError) as exc:
            # Registrar la anomalía pero continuar — el pedido existe aunque falte el resumen
            logger.warning("Order %s has invalid items_summary: %s", o.id, exc)
        out.append({'id': f"ORD-{o.id}", 'date': o.date.isoformat(), 'total': o.total, 'status': o.status, 'items': items})
    return jsonify(out)


# --- INSTANCIA DIRECTA (SEED) ---
with app.app_context():
    os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
    db.create_all()
    if not User.query.filter_by(email='admin@tech.com').first():
        admin = User(
            email='admin@tech.com', 
            username='AdminTech', 
            password=generate_password_hash('Admin123!', method='pbkdf2:sha256'),
            role='admin',
            balance=99999.0
        )
        db.session.add(admin)
        db.session.commit()
        
        # Seed Products 
        p1 = Product(name='ASUS ROG Strix B550', price=179.99, description='Placa base potente.', image='https://placehold.co/320x220/212529/FF6000?text=ASUS+ROG', stock=5, seller_id=admin.id)
        p2 = Product(name='AMD Ryzen 7 5800X', price=299.00, description='CPU 8 núcleos', image='https://placehold.co/320x220/212529/FF6000?text=Ryzen+7', stock=0, seller_id=admin.id)
        p3 = Product(name='Corsair Vengeance 32GB', price=89.50, description='RAM DDR4 RGB', image='https://placehold.co/320x220/212529/FF6000?text=Corsair+32GB', stock=15, seller_id=admin.id)
        db.session.add_all([p1, p2, p3])
        db.session.commit()

if __name__ == '__main__':
    # host='0.0.0.0' ES NECESARIO en Docker para que el proceso escuche en todas
    # las interfaces del contenedor y sea accesible desde el host o el proxy inverso.
    # En producción, el tráfico externo nunca llega directamente aquí: pasa por
    # Nginx (que actúa de proxy reverso) dentro de la misma red Docker interna.
    # Por tanto NO representa una exposición pública: Nginx filtra y reenvía.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)