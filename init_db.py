from app import app, db, User, Post, Comment

def init_db():
    """
    Inicializa la base de datos creando todas las tablas
    y agregando datos iniciales.
    """
    with app.app_context():
        # Crear todas las tablas
        db.create_all()
        
        # Agregar usuario administrador si no existe
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin123')
            db.session.add(admin)
            db.session.commit()
            print("[+] Usuario administrador creado")
        else:
            print("[*] El usuario administrador ya existe")
        
        # Agregar algunos posts iniciales si no existen
        if Post.query.count() == 0:
            posts = [
                Post(
                    title='Introducción a la Seguridad Web',
                    content="""La seguridad web es esencial para proteger datos sensibles en aplicaciones web modernas.
                    
Las aplicaciones web están expuestas a múltiples amenazas que pueden comprometer:
- La integridad de los datos
- La confidencialidad de la información
- La disponibilidad de los servicios

El OWASP Top 10 es una lista de las vulnerabilidades web más críticas, que incluye inyección SQL, XSS, CSRF, entre otras que exploraremos en este blog.""",
                    author='admin'
                ),
                Post(
                    title='¿Qué es SQL Injection?',
                    content="""SQL Injection es una vulnerabilidad que permite a un atacante insertar código SQL malicioso en consultas que la aplicación envía a la base de datos.

Un ataque SQL Injection exitoso puede resultar en:
1. Acceso no autorizado a datos sensibles
2. Modificación o eliminación de información
3. Escalada de privilegios
4. Ejecución de comandos en el sistema operativo (en algunos casos)

Los ataques de inyección SQL básicos suelen usar caracteres como comillas (') para romper la sintaxis de una consulta SQL y agregar código malicioso.""",
                    author='admin'
                ),
                Post(
                    title='Protección contra XSS',
                    content="""Cross-Site Scripting (XSS) es una vulnerabilidad donde los atacantes pueden inyectar scripts maliciosos que se ejecutan en el navegador de los usuarios.

Existen tres tipos principales:
- XSS Reflejado: El script malicioso viene en la solicitud y se refleja en la respuesta
- XSS Almacenado: El script malicioso se guarda en la base de datos y se muestra a múltiples usuarios
- XSS basado en DOM: La vulnerabilidad está en el código JavaScript del lado del cliente

Para protegerse contra XSS, es fundamental:
1. Validar todas las entradas de usuario
2. Utilizar técnicas de escape de contenido adecuadas
3. Implementar encabezados de seguridad como Content-Security-Policy""",
                    author='admin'
                ),
                Post(
                    title='Ataques CSRF Explicados',
                    content="""Cross-Site Request Forgery (CSRF) es un ataque que fuerza a un usuario autenticado a ejecutar acciones no deseadas en una aplicación web en la que está autenticado.

Un ataque CSRF típicamente funciona así:
1. El usuario inicia sesión en un sitio legítimo (como su banco)
2. Sin cerrar sesión, el usuario visita un sitio malicioso
3. El sitio malicioso contiene código que realiza una solicitud al sitio legítimo
4. El navegador envía automáticamente las cookies de autenticación con la solicitud
5. La acción no deseada se ejecuta con los privilegios del usuario

La protección contra CSRF generalmente implica el uso de tokens anti-CSRF que deben validarse en cada solicitud que modifica datos.""",
                    author='admin'
                ),
                Post(
                    title='Clickjacking: El arte del engaño visual',
                    content="""Clickjacking es una técnica de ataque donde un usuario es engañado para hacer clic en algo diferente de lo que percibe, potencialmente revelando información confidencial o tomando control de su dispositivo.

En un ataque típico de clickjacking:
1. El atacante crea una página web que contiene un iframe con el sitio vulnerable
2. El iframe se oculta o hace casi invisible 
3. Encima del iframe, el atacante coloca contenido atractivo (como un botón de "Descargar" o "Ganar premio")
4. Cuando el usuario hace clic en lo que ve, en realidad está interactuando con el sitio vulnerable cargado en el iframe

La protección principal contra clickjacking es implementar el encabezado HTTP X-Frame-Options establecido en DENY o SAMEORIGIN.""",
                    author='admin'
                ),
                Post(
                    title='Redirecciones Abiertas (Open Redirect)',
                    content="""Las redirecciones abiertas son vulnerabilidades que permiten a un atacante redirigir a los usuarios a sitios maliciosos utilizando un parámetro no validado en la URL.

La cadena de ataque típica es:
1. El atacante crea un enlace con una URL de redirección maliciosa 
2. La víctima hace clic en el enlace, que apunta al sitio legítimo
3. El sitio legítimo redirige al usuario a la URL maliciosa
4. El usuario, confiando en el sitio original, puede ser víctima de phishing

Para prevenir redirecciones abiertas se debe:
- Evitar usar redirecciones basadas en parámetros URL
- Si es necesario usarlas, validar las URLs contra una lista blanca
- Usar redirecciones indirectas a través de una página intermedia""",
                    author='admin'
                )
            ]
            for post in posts:
                db.session.add(post)
            db.session.commit()
            print("[+] Posts iniciales creados")
        else:
            print("[*] Ya existen posts en la base de datos")

if __name__ == "__main__":
    init_db()
    print("[+] Base de datos inicializada correctamente")