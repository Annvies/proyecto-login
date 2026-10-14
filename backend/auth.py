"""Lógica de autenticación: hashing, validaciones y acceso a la base de datos.

Solo usa la biblioteca estándar de Python (hashlib, hmac, secrets, sqlite3).
Nunca se imprimen contraseñas ni hashes.
"""
import hashlib
import hmac
import os
import secrets
import sqlite3

ITERACIONES = 120_000
LONGITUD_MINIMA = 9
LONGITUD_SALT = 16

# Rutas resueltas a partir de __file__ para que funcionen sin importar el
# directorio de trabajo desde el que se invoque el código.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "login.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "db", "schema.sql")


def hash_password(password, salt=None):
    """Deriva (hash_hex, salt_hex) con PBKDF2-HMAC-SHA256 (120000 iteraciones).

    Si no se recibe una sal, genera una nueva y única por usuario.
    """
    if salt is None:
        salt = secrets.token_hex(LONGITUD_SALT)
    derivada = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        ITERACIONES,
    )
    return derivada.hex(), salt


def verify_password(password, salt, hash_esperado):
    """Compara una contraseña con su hash en tiempo constante."""
    calculado, _ = hash_password(password, salt)
    return hmac.compare_digest(calculado, hash_esperado)


def validar_email(email):
    """Devuelve True si el email tiene forma usuario@dominio.tld.

    Reglas: exactamente un "@", sin espacios en blanco, parte local no vacía
    y sin puntos al inicio/fin, dominio no vacío con un "." y sin puntos
    al inicio/fin.
    """
    if not isinstance(email, str):
        return False
    email = email.strip()
    if email.count("@") != 1:
        return False
    if any(caracter.isspace() for caracter in email):
        return False
    usuario, _, dominio = email.partition("@")
    if not usuario or not dominio:
        return False
    if usuario.startswith(".") or usuario.endswith("."):
        return False
    if dominio.startswith(".") or dominio.endswith("."):
        return False
    return "." in dominio


def validar_password(password):
    """Devuelve True si la contraseña tiene al menos 8 caracteres."""
    return isinstance(password, str) and len(password) >= LONGITUD_MINIMA


def conectar(ruta_db):
    """Abre una conexión SQLite con filas tipo diccionario."""
    conexion = sqlite3.connect(ruta_db, check_same_thread=False)
    conexion.row_factory = sqlite3.Row
    return conexion


def inicializar(ruta_db, ruta_schema):
    """Abre la base de datos y aplica el esquema (la crea si no existe)."""
    conexion = conectar(ruta_db)
    with open(ruta_schema, encoding="utf-8") as archivo:
        conexion.executescript(archivo.read())
    conexion.commit()
    return conexion


def crear_usuario(conexion, email=None, password=None):
    """Registra un usuario y devuelve su id.

    Acepta dos formas de llamada:
        crear_usuario(conexion, email, password)  # usa una conexión existente
        crear_usuario(email, password)            # abre la BD por defecto

    Lanza ValueError si los datos son inválidos y sqlite3.IntegrityError
    si el email ya está registrado.
    """
    cerrar = False
    if not isinstance(conexion, sqlite3.Connection):
        # Forma (email, password): el primer argumento es el email.
        password = email
        email = conexion
        conexion = inicializar(DB_PATH, SCHEMA_PATH)
        cerrar = True
    try:
        if not validar_email(email) or not validar_password(password):
            raise ValueError("Email o contraseña inválidos.")
        email = email.strip().lower()
        hash_, salt = hash_password(password)
        cursor = conexion.execute(
            "INSERT INTO usuarios (email, password_hash, salt) VALUES (?, ?, ?)",
            (email, hash_, salt),
        )
        conexion.commit()
        return cursor.lastrowid
    finally:
        if cerrar:
            conexion.close()


def autenticar(conexion, email=None, password=None):
    """Devuelve True si las credenciales son correctas.

    Acepta dos formas de llamada:
        autenticar(conexion, email, password)
        autenticar(email, password)
    """
    cerrar = False
    if not isinstance(conexion, sqlite3.Connection):
        password = email
        email = conexion
        conexion = inicializar(DB_PATH, SCHEMA_PATH)
        cerrar = True
    try:
        if not isinstance(email, str) or not isinstance(password, str):
            return False
        email = email.strip().lower()
        fila = conexion.execute(
            "SELECT password_hash, salt FROM usuarios WHERE email = ?", (email,)
        ).fetchone()
        if fila is None:
            return False
        return verify_password(password, fila["salt"], fila["password_hash"])
    finally:
        if cerrar:
            conexion.close()