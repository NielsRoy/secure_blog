#!/usr/bin/env python
import os
from app import app
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

if __name__ == "__main__":
    # Obtener el puerto desde la variable de entorno o usar 5000 por defecto
    port = int(os.environ.get('PORT', 5000))
    
    # Opciones de ejecución seguras para entorno de producción
    # En producción, debug debe estar desactivado
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Para habilitar HTTPS en desarrollo, descomentar la siguiente línea y asegurarse de tener instalado 'pip install cryptography'
    # app.run(host='0.0.0.0', port=port, debug=debug_mode, ssl_context='adhoc')
    
    # Versión sin SSL para desarrollo local
    app.run(host='0.0.0.0', port=port, debug=debug_mode)