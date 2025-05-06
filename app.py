from flask import Flask, render_template, request, redirect, session, url_for, make_response, flash
from flask_sqlalchemy import SQLAlchemy
import os
import re
from sqlalchemy.sql import text
import secrets
from markupsafe import escape
import bleach
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# Generación de clave secreta fuerte
app.secret_key = secrets.token_hex(32)  # Genera una clave secreta de 64 caracteres hexadecimales

# Configuración de PostgreSQL
# URL de conexión para Railway: postgresql://postgres:password@containers-us-west-10.railway.app:5432/railway
# Para desarrollo local, ajusta según tu configuración
db_url = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/vulnerable_blog')
# Asegurarse de que la URL empiece con postgresql:// (Railway usa postgres://)
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configurar protección CSRF
csrf = CSRFProtect(app)

db = SQLAlchemy(app)

# Definición de modelos
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # En producción usar password_hash y bcrypt

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(50), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Contenido será sanitizado antes de almacenarse

# Función para inicializar la base de datos
def init_db():
    with app.app_context():
        db.create_all()
        
        # Agregar usuario por defecto si no existe
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin123')  # En producción usar bcrypt.generate_password_hash
            db.session.add(admin)
            db.session.commit()
        
        # Agregar algunos posts por defecto si no existen
        if Post.query.count() == 0:
            posts = [
                Post(title='Introducción a la Seguridad Web', 
                     content='La seguridad web es esencial para proteger datos sensibles. Las aplicaciones web modernas están expuestas a múltiples amenazas que pueden comprometer la integridad, confidencialidad y disponibilidad de los datos. Este blog explorará las vulnerabilidades más comunes y cómo mitigarlas.', 
                     author='admin'),
                Post(title='¿Qué es SQL Injection?', 
                     content='SQL Injection es una vulnerabilidad común que permite a un atacante insertar código SQL malicioso en consultas que la aplicación envía a la base de datos. Esto puede resultar en acceso no autorizado a datos sensibles, modificación de información e incluso control completo del servidor. Es una de las vulnerabilidades más peligrosas en aplicaciones web.', 
                     author='admin'),
                Post(title='Protección contra XSS', 
                     content='Cross-Site Scripting (XSS) es una vulnerabilidad donde los atacantes pueden inyectar scripts maliciosos que se ejecutan en el navegador de los usuarios. Existen tres tipos principales: Reflected XSS, Stored XSS y DOM-based XSS. Para protegerse, es fundamental validar todas las entradas de usuario y utilizar técnicas de escape de contenido adecuadas.', 
                     author='admin')
            ]
            for post in posts:
                db.session.add(post)
            db.session.commit()

# Configuración de Bleach para sanitizar HTML
allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre']
allowed_attrs = {'*': ['class']}

def sanitize_html(content):
    return bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)

# Lista blanca de URLs permitidas para redireccionamiento
ALLOWED_REDIRECT_DOMAINS = {
    'localhost',
    '127.0.0.1',
    'example.com',
    'yourdomain.com'
}

deployment_domain = os.environ.get('DEPLOYMENT_DOMAIN')
if deployment_domain:
    ALLOWED_REDIRECT_DOMAINS.add(deployment_domain)

def is_safe_redirect_url(url):
    # Verificar si la URL es relativa (comienza sin esquema)
    if url.startswith('/'):
        return True
    
    # Verificar si la URL pertenece a dominios permitidos
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        return parsed_url.netloc in ALLOWED_REDIRECT_DOMAINS
    except:
        return False

# Rutas de la aplicación
@app.route('/')
def index():
    # Consulta segura utilizando SQLAlchemy ORM
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts, username=session.get('username'))

@app.route('/search')
def search():
    q = request.args.get('q', '')
    
    # Consulta segura utilizando SQLAlchemy ORM con parámetros
    posts = Post.query.filter(
        (Post.title.ilike(f"%{q}%")) | (Post.content.ilike(f"%{q}%"))
    ).all()
    
    return render_template('search.html', posts=posts, query=q, username=session.get('username'))

@app.route('/post/<int:post_id>')
def view_post(post_id):
    # Consulta segura utilizando SQLAlchemy ORM
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    
    return render_template('post.html', post=post, comments=comments, username=session.get('username'))

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if not session.get('username'):
        return redirect(url_for('login'))
    
    comment_content = request.form.get('comment', '')
    
    # Sanitizar el contenido del comentario para prevenir XSS
    sanitized_content = sanitize_html(comment_content)
    
    new_comment = Comment(
        post_id=post_id,
        author=session['username'],
        content=sanitized_content
    )
    
    db.session.add(new_comment)
    db.session.commit()
    
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Consulta segura utilizando SQLAlchemy ORM con filtros
        user = User.query.filter_by(username=username, password=password).first()
        
        if user:
            session['username'] = username
            
            # Implementar regeneración de sesión para prevenir ataques de fijación de sesión
            session_id = session.get('_id')
            session.clear()
            session['_id'] = session_id
            session['username'] = username
            
            # Redirigir a la página que intentaba acceder o al índice
            next_page = request.args.get('next')
            if next_page and is_safe_redirect_url(next_page):
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            error = 'Credenciales inválidas. Inténtalo de nuevo.'
    
    return render_template('login.html', error=error, username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validar entrada
        if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
            error = 'El nombre de usuario debe contener solo letras, números y guiones bajos (3-50 caracteres).'
        elif len(password) < 8:
            error = 'La contraseña debe tener al menos 8 caracteres.'
        else:
            # Verificar si el usuario ya existe
            existing_user = User.query.filter_by(username=username).first()
            
            if existing_user:
                error = 'El nombre de usuario ya está en uso. Elige otro.'
            else:
                # En producción, hashear la contraseña
                # password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
                # new_user = User(username=username, password=password_hash)
                new_user = User(username=username, password=password)
                db.session.add(new_user)
                db.session.commit()
                
                session['username'] = username
                return redirect(url_for('index'))
    
    return render_template('register.html', error=error, username=session.get('username'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('username'):
        return redirect(url_for('login'))
    
    # CSRF está protegido por el middleware CSRF global
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        # Validación de contraseña
        if len(new_password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres.', 'danger')
            return redirect(url_for('profile'))
        
        # Actualizar contraseña
        user = User.query.filter_by(username=session['username']).first()
        if user:
            # En producción, hashear la contraseña
            # user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = new_password
            db.session.commit()
            # Usando el patrón PRG (Post/Redirect/Get) para evitar reenvío de formulario
            flash('Contraseña actualizada correctamente.', 'success')
            return redirect(url_for('profile'))
    
    return render_template('profile.html', username=session.get('username'))

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if not session.get('username'):
        return redirect(url_for('login'))

    # La protección CSRF está habilitada globalmente
    # Eliminar usuario
    user = User.query.filter_by(username=session['username']).first()
    if user:
        # Eliminar comentarios del usuario
        Comment.query.filter_by(author=session['username']).delete()
        
        # Eliminar posts del usuario
        Post.query.filter_by(author=session['username']).delete()
        
        # Eliminar usuario
        db.session.delete(user)
        db.session.commit()
        
        # Cerrar sesión
        session.clear()
        
        # Informar al usuario que la cuenta ha sido eliminada
        flash('Tu cuenta ha sido eliminada permanentemente', 'success')
        
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    # Eliminar la sesión por completo en lugar de solo eliminar username
    session.clear()
    return redirect(url_for('index'))

@app.route('/about')
def about():
    return render_template('about.html', username=session.get('username'))

@app.route('/redirect')
def open_redirect():
    # Capturar la URL de redirección del parámetro
    url = request.args.get('url', '')
    
    # Validar contra lista blanca de URLs permitidas
    if url and is_safe_redirect_url(url):
        # En lugar de redirigir directamente, mostrar una página intermedia
        return render_template('redirect_warning.html', redirect_url=url)
    
    # Si la URL no es segura, redirigir al índice
    flash('La redirección solicitada no es segura y ha sido bloqueada.', 'warning')
    return redirect(url_for('index'))

@app.after_request
def add_security_headers(response):
    # Configuración de Content Security Policy (CSP)
    csp = "default-src 'self'; " \
          "script-src 'self' https://cdn.jsdelivr.net; " \
          "style-src 'self' https://cdn.jsdelivr.net 'sha256-zpKajlEgRfSYQJkblFwQbXywe3j8zrxakgITpalXCcg='; " \
          "img-src 'self' data:; " \
          "font-src 'self' https://cdn.jsdelivr.net; " \
          "connect-src 'self'; " \
          "frame-ancestors 'self'; " \
          "form-action 'self'"
    
    # Agregar headers de seguridad
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Protección contra clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Inicializar la base de datos al arrancar la aplicación
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Desactivar modo debug en producción
    app.run(host='0.0.0.0', port=port, debug=False)