from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db2433.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Field to identify admin users

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_file = db.Column(db.String(120), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Link to User model

    # Add relationship
    admin = db.relationship('User', backref='products')  # Use 'User' instead of 'Admin'


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Change 'user' to 'users'
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)  # Change 'product' to 'products'
    quantity = db.Column(db.Integer, nullable=False, default=1)

    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)



from werkzeug.security import generate_password_hash, check_password_hash

# During registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form.get('admin') == 'on'  # Checkbox for admin registration

        hashed_password = generate_password_hash(password)  # Use default hash method
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')




# During login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home' if user.is_admin else 'home'))
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Query products only for the logged-in admin
    products = Product.query.filter_by(admin_id=current_user.id).all()  # Corrected to use admin_id
    return render_template('admin_dashboard.html', products=products)





from flask_login import current_user

import os

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        product_name = request.form['name']
        product_category = request.form['category']
        product_description = request.form['description']
        product_price = request.form['price']
        product_image = request.files['image']

        # Check if an image was uploaded
        if product_image and product_image.filename != '':
            # Save the image
            image_filename = product_image.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            product_image.save(image_path)  # Save the image to static/uploads/

            # Create a new product instance
            new_product = Product(
                name=product_name,
                category=product_category,
                description=product_description,
                price=product_price,
                image_file=image_filename,  # Save only the filename to the database
                admin_id=current_user.id  # Assign current admin ID
            )

            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully!')  # Add a success message
            return redirect(url_for('admin_dashboard'))

        else:
            flash('No image uploaded or invalid image. Please try again.')  # Error message

    return render_template('add_product.html')


@app.route('/product/<int:product_id>')
def product(product_id):
    product = Product.query.get_or_404(product_id)  # Fetch the product
    return render_template('product.html', product=product)  # Render product page


@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        product.name = request.form['name']
        product.category = request.form['category']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        # Handle the image upload and saving here if needed
        db.session.commit()
        flash('Product updated successfully!')
        return redirect(url_for('admin_dashboard'))  # Redirect to your homepage or wherever you need

    return render_template('update_product.html', product=product)


@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get(product_id)
    if product and product.admin_id == current_user.id:  # Check if admin owns the product
        db.session.delete(product)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    else:
        return "You do not have permission to delete this product.", 403



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
    quantity = int(request.args.get('quantity', 1))  # Get the quantity from the query parameters

    # Check if the product is already in the cart
    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += quantity  # Update quantity if already exists
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
    total = sum(item.product.price * item.quantity for item in cart_items)  # Calculate total here
    return render_template('cart.html', cart_items=cart_items, total=total)  # Pass total to template


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
