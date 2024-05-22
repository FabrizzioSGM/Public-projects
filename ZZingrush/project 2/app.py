from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from functions import allowed_file, login_required, apology, is_password_complex
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///products.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/product_images'
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    hash = db.Column(db.String(200))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', back_populates='users')
    email = db.Column(db.String(100), unique=True)
    managed_teams = db.relationship('Team', back_populates='manager')
    teams = db.relationship('Team', secondary='team_members', back_populates='members')

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    users = db.relationship('User', back_populates='role')

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    manager = db.relationship('User', back_populates='managed_teams')
    members = db.relationship('User', secondary='team_members', back_populates='teams')
    products = db.relationship('Product', back_populates='team')

team_members = db.Table('team_members',
    db.Column('team_id', db.Integer, db.ForeignKey('team.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    image_filename = db.Column(db.String(100))
    team = db.relationship('Team', back_populates='products')
@app.route('/Admin/roles', methods=['GET', 'POST'])
@login_required
def manage_roles():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user or user.role.name != 'admin':
        flash('Acceso denegado: Solo los administradores pueden gestionar roles.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)

        if action == 'update_role':
            new_role_id = request.form.get('new_role')
            new_role = Role.query.get(new_role_id)
            if user and new_role:
                user.role_id = new_role_id
                db.session.commit()
                flash('El rol del usuario ha sido actualizado.', 'success')
            else:
                flash('Usuario o rol no encontrado.', 'danger')

        elif action == 'delete_user' and user:
            db.session.delete(user)
            db.session.commit()
            flash('Usuario eliminado exitosamente.', 'success')

    users = User.query.filter(User.role.has(Role.name != 'admin')).all()
    roles = Role.query.filter(Role.name != 'admin').all()
    return render_template('roles.html', users=users, roles=roles)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        username = request.form.get("username")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            flash("Debe completar todos los campos")
            return redirect(url_for('register'))

        if confirmation != password:
            flash("La contraseña y la confirmación de la contraseña no coinciden")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("El correo electrónico ya está en uso")
            return redirect(url_for('register'))

        if not is_password_complex(password):
            flash("La contraseña debe contener al menos una letra, un número y un símbolo")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("El nombre de usuario ya está en uso")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        customer_role = Role.query.filter_by(name='customer').first()
        if not customer_role:
            flash("Rol de cliente no encontrado. Contacte al administrador.")
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, hash=hashed_password, role_id=customer_role.id)
        db.session.add(new_user)
        db.session.commit()

        session["user_id"] = new_user.id
        flash("¡Registrado exitosamente!")
        return redirect(url_for('index'))
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Debe proporcionar un nombre de usuario y una contraseña")
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.hash, password):
            flash("Nombre de usuario o contraseña inválidos")
            return redirect(url_for('login'))

        session["user_id"] = user.id
        return redirect(url_for('index'))
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/add_role', methods=['POST'])
@login_required
def add_role():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user or user.role.name != 'admin':
        flash('Acceso denegado: Solo los administradores pueden gestionar roles.', 'danger')
        return redirect(url_for('index'))

    role_name = request.form.get('role_name')
    if role_name:
        new_role = Role(name=role_name)
        db.session.add(new_role)
        db.session.commit()
        flash('Rol agregado exitosamente.', 'success')
    else:
        flash('Debe proporcionar un nombre para el rol.', 'danger')

    return redirect(url_for('manage_roles'))

@app.route('/delete_role/<int:role_id>', methods=['POST'])
@login_required
def delete_role(role_id):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user or user.role.name != 'admin':
        flash('Acceso denegado: Solo los administradores pueden gestionar roles.', 'danger')
        return redirect(url_for('index'))

    role = Role.query.get(role_id)
    if role and role.name != 'admin':
        db.session.delete(role)
        db.session.commit()
        flash('Rol eliminado exitosamente.', 'success')
    else:
        flash('No se puede eliminar este rol.', 'danger')

    return redirect(url_for('manage_roles'))
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('nombre')
        quantity = request.form.get('cantidad')
        price = request.form.get('precio')
        image = request.files.get('imagen')

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        new_product = Product(
            user_id=user_id,
            team_id=user.teams[0].id if user.teams else None,
            name=name,
            price=float(price),
            quantity=int(quantity),
            image_filename=filename
        )
        db.session.add(new_product)
        db.session.commit()
    products = None
    if user.role.name == 'manager':
        products = Product.query.filter_by(user_id=user_id).all()
    else:
        products = Product.query.all()

    return render_template('index.html', products=products, user=user)
@app.route('/actualizar/<int:product_id>', methods=['POST'])
@login_required
def actualizar(product_id):
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('login'))

    product = Product.query.get(product_id)
    if not product:
        flash('Producto no encontrado.', 'danger')
        return redirect(url_for('index'))

    new_quantity = request.form.get('cantidad')
    new_price = request.form.get('precio')

    try:
        product.quantity = int(new_quantity)
        product.price = float(new_price)
        db.session.commit()
        flash('Producto actualizado exitosamente.', 'success')
    except ValueError:
        flash('Cantidad o precio inválidos.', 'danger')

    return redirect(url_for('index'))
@app.route('/borrar/<int:product_id>', methods=['POST'])
@login_required
def borrar_producto(product_id):
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('login'))

    product = Product.query.get(product_id)
    if not product:
        flash('Producto no encontrado.', 'danger')
        return redirect(url_for('index'))

    db.session.delete(product)
    db.session.commit()

    flash('Producto eliminado exitosamente.', 'success')
    return redirect(url_for('index'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Insert roles if they do not exist
        roles = ['customer', 'manager', 'admin', 'supplier', 'support', 'guest']
        for role_name in roles:
            if not Role.query.filter_by(name=role_name).first():
                role = Role(name=role_name)
                db.session.add(role)
        db.session.commit()

    app.run(debug=True)
