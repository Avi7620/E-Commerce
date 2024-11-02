from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db12.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Google Drive API Setup
SCOPES = ['https://www.googleapis.com/auth/drive.file']
creds = None

def authenticate_gdrive():
    global creds
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_file = db.Column(db.String(120), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    admin = db.relationship('User', backref='products')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form.get('admin') == 'on'
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard' if user.is_admin else 'home'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    products = Product.query.filter_by(admin_id=current_user.id).all()
    return render_template('admin_dashboard.html', products=products)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        product_name = request.form['name']
        product_category = request.form['category']
        product_description = request.form['description']
        product_price = request.form['price']
        product_image = request.files['image']

        if product_image:
            try:
                authenticate_gdrive()
                drive_service = build('drive', 'v3', credentials=creds)

                file_metadata = {
                    'name': product_image.filename,
                    'mimeType': product_image.content_type
                }
                media = MediaFileUpload(product_image, mimetype=product_image.content_type)
                file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
                image_file_id = file.get('id')

                new_product = Product(
                    name=product_name,
                    category=product_category,
                    description=product_description,
                    price=product_price,
                    image_file=image_file_id,
                    admin_id=current_user.id
                )

                db.session.add(new_product)
                db.session.commit()
                flash('Product added successfully!')
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                flash(f'An error occurred while uploading the image: {e}')
        else:
            flash('No image uploaded or invalid image. Please try again.')

    return render_template('add_product.html')

@app.route('/product/<int:product_id>')
def product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product.html', product=product)

@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        product.name = request.form['name']
        product.category = request.form['category']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        db.session.commit()
        flash('Product updated successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('update_product.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get(product_id)
    if product and product.admin_id == current_user.id:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!')
    else:
        flash('You do not have permission to delete this product.')
    return redirect(url_for('admin_dashboard'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    products = []
    if request.method == 'POST':
        query = request.form['query']
        products = Product.query.filter(Product.name.contains(query) | Product.category.contains(query)).all()
    return render_template('search.html', products=products)

@app.route('/add_to_cart/<int:product_id>', methods=['GET', 'POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    quantity = int(request.args.get('quantity', 1))

    # Check if the product is already in the cart
    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)

    db.session.commit()
    flash('Item added to cart successfully!')
    return redirect(url_for('home'))

@app.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/delete_cart_item/<int:item_id>', methods=['POST'])
@login_required
def delete_cart_item(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.user_id == current_user.id:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart.')
    else:
        flash('You cannot remove this item.')
    return redirect(url_for('cart'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Initializes the database tables within application context
    app.run(debug=True)
