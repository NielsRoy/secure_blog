import os
import secrets
from dotenv import load_dotenv

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Configuración para la base de datos
class Config:
    # URL de conexión para PostgreSQL
    # Si la variable DATABASE_URL no está en el entorno, se usa la URL por defecto
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/vulnerable_blog')
    
    # Si la URL comienza con "postgres://", reemplazarla por "postgresql://" para compatibilidad con SQLAlchemy
    if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace("postgres://", "postgresql://", 1)
    
    # Desactivar el seguimiento de modificaciones para mejorar el rendimiento
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Clave secreta para la aplicación - generada de forma segura
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    
    # Modo debug desactivado por defecto en producción
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Configuración de seguridad para entorno de producción
    # En desarrollo local sin HTTPS, estas opciones pueden causar problemas
    SESSION_COOKIE_SECURE = False  # Cambiar a True cuando se use HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Prevenir acceso a cookies desde JavaScript
    SESSION_COOKIE_SAMESITE = 'Lax'  # Prevenir CSRF
    PERMANENT_SESSION_LIFETIME = 3600  # Expiración de sesión en segundos (1 hora)
    
    # Configuración de WTForms
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', secrets.token_hex(32))