"""Servidor HTTP del login: expone la API JSON y sirve el frontend.

Ejecución desde la raíz de proyecto-login/:
    python -m backend.app
"""
import json
import os
import secrets
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend import auth

DB_PATH = auth.DB_PATH
SCHEMA_PATH = auth.SCHEMA_PATH
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

# Sesiones en memoria: token -> email.
SESIONES = {}

_CONEXION_DEFECTO = None


def _conexion_por_defecto():
    """Conexión única a la BD por defecto para llamadas directas a dispatch."""
    global _CONEXION_DEFECTO
    if _CONEXION_DEFECTO is None:
        _CONEXION_DEFECTO = auth.conectar(DB_PATH)
    return _CONEXION_DEFECTO


def generar_token():
    """Genera un token de sesión aleatorio y seguro."""
    return secrets.token_urlsafe(32)


def manejar_registro(conexion, cuerpo):
    """Registra un usuario. Devuelve (status, dict)."""
    if not isinstance(cuerpo, dict):
        return 400, {"ok": False, "error": "JSON inválido."}
    email = str(cuerpo.get("email", ""))
    password = str(cuerpo.get("password", ""))
    if not auth.validar_email(email):
        return 400, {"ok": False, "error": "Correo inválido."}
    if not auth.validar_password(password):
        return 400, {"ok": False, "error": "La contraseña debe tener al menos 8 caracteres."}
    try:
        auth.crear_usuario(conexion, email, password)
    except sqlite3.IntegrityError:
        return 409, {"ok": False, "error": "Ese correo ya está registrado."}
    except ValueError:
        return 400, {"ok": False, "error": "Datos inválidos."}
    return 201, {"ok": True, "mensaje": "Usuario registrado."}


def manejar_login(conexion, sesiones, cuerpo):
    """Inicia sesión y devuelve un token. Devuelve (status, dict)."""
    if not isinstance(cuerpo, dict):
        return 400, {"ok": False, "error": "JSON inválido."}
    email = str(cuerpo.get("email", "")).strip().lower()
    password = str(cuerpo.get("password", ""))
    if not auth.autenticar(conexion, email, password):
        return 401, {"ok": False, "error": "Correo o contraseña incorrectos."}
    token = generar_token()
    sesiones[token] = email
    return 200, {"ok": True, "email": email, "token": token}


def manejar_me(sesiones, encabezados):
    """Valida 'Authorization: Bearer <token>' y devuelve el email."""
    encabezados = encabezados or {}
    encabezado = encabezados.get("Authorization", "")
    if not encabezado.startswith("Bearer "):
        return 401, {"ok": False, "error": "No autenticado."}
    token = encabezado[len("Bearer "):].strip()
    email = sesiones.get(token)
    if email is None:
        return 401, {"ok": False, "error": "No autenticado."}
    return 200, {"ok": True, "email": email}


def dispatch(metodo, ruta, cuerpo, encabezados, conexion=None, sesiones=None):
    """Resuelve una petición de la API y devuelve (status, dict).

    Si no se pasan conexión/sesiones, usa la BD por defecto y el registro
    de sesiones del módulo.
    """
    if conexion is None:
        conexion = _conexion_por_defecto()
    if sesiones is None:
        sesiones = SESIONES
    ruta = ruta.split("?", 1)[0]
    if metodo == "POST" and ruta == "/api/register":
        return manejar_registro(conexion, cuerpo)
    if metodo == "POST" and ruta == "/api/login":
        return manejar_login(conexion, sesiones, cuerpo)
    if metodo == "GET" and ruta == "/api/me":
        return manejar_me(sesiones, encabezados)
    return 404, {"ok": False, "error": "Ruta no encontrada."}


class ManejadorLogin(BaseHTTPRequestHandler):
    @property
    def conexion(self):
        return self.server.conexion

    @property
    def sesiones(self):
        return self.server.sesiones

    def _responder(self, codigo, cuerpo):
        datos = json.dumps(cuerpo).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def _leer_json(self):
        try:
            longitud = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            longitud = 0
        if longitud <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(longitud).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _servir_archivo(self, nombre, tipo):
        ruta = os.path.join(FRONTEND_DIR, nombre)
        if not os.path.isfile(ruta):
            self.send_error(404)
            return
        with open(ruta, "rb") as archivo:
            contenido = archivo.read()
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(contenido)))
        self.end_headers()
        self.wfile.write(contenido)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._servir_archivo("index.html", "text/html; charset=utf-8")
        elif self.path == "/styles.css":
            self._servir_archivo("styles.css", "text/css; charset=utf-8")
        elif self.path == "/app.js":
            self._servir_archivo("app.js", "text/javascript; charset=utf-8")
        elif self.path.startswith("/api/"):
            self._responder(
                *dispatch("GET", self.path, None, self.headers, self.conexion, self.sesiones)
            )
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.startswith("/api/"):
            cuerpo = self._leer_json()
            self._responder(
                *dispatch("POST", self.path, cuerpo, self.headers, self.conexion, self.sesiones)
            )
        else:
            self.send_error(404)

    def log_message(self, formato, *args):
        # No se registran contraseñas ni hashes en consola.
        return


def crear_servidor(host="127.0.0.1", puerto=8000, ruta_db=DB_PATH):
    """Crea un ThreadingHTTPServer listo, con su conexión y sesiones propias."""
    conexion = auth.inicializar(ruta_db, SCHEMA_PATH)
    servidor = ThreadingHTTPServer((host, puerto), ManejadorLogin)
    servidor.conexion = conexion
    servidor.sesiones = {}
    return servidor


def ejecutar():
    servidor = crear_servidor()
    print("Login disponible en http://127.0.0.1:8000  (Ctrl+C para detener)")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        servidor.server_close()
        servidor.conexion.close()


if __name__ == "__main__":
    ejecutar()