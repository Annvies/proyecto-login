"""Crea (o reinicia) la base de datos SQLite del login a partir del esquema.

Solo usa la biblioteca estandar de Python (sqlite3, hashlib, hmac, secrets).

Uso:
    python -m db.init_db
"""
import hashlib
import hmac
import os
import secrets
import sqlite3

# Rutas resueltas a partir de __file__ para que sean robustas sin importar
# el directorio de trabajo desde el que se invoque el script.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "login.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

EMAIL_DEMO = "demo@login.com"
PASSWORD_DEMO = "demo1234"

ITERACIONES = 120_000
LONGITUD_SALT = 16


def generar_hash(password, salt=None):
    """Devuelve (password_hash_hex, salt_hex) usando PBKDF2-HMAC-SHA256.

    Si no se recibe una sal, genera una nueva y unica por usuario.
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


def verificar_hash(password, salt, hash_esperado):
    """Compara una contrasena con su hash almacenado en tiempo constante."""
    calculado, _ = generar_hash(password, salt)
    return hmac.compare_digest(calculado, hash_esperado)


def reiniciar(
    ruta=DB_PATH,
    ruta_schema=SCHEMA_PATH,
    email=EMAIL_DEMO,
    password=PASSWORD_DEMO,
):
    """Borra la base anterior, aplica el esquema e inserta el usuario demo.

    La contrasena solo se usa para derivar el hash: nunca se persiste en claro.
    Devuelve la ruta absoluta de la base de datos creada.
    """
    if os.path.exists(ruta):
        os.remove(ruta)

    conexion = sqlite3.connect(ruta)
    try:
        with open(ruta_schema, encoding="utf-8") as archivo:
            conexion.executescript(archivo.read())

        password_hash, salt = generar_hash(password)
        conexion.execute(
            "INSERT INTO usuarios (email, password_hash, salt) VALUES (?, ?, ?)",
            (email.strip().lower(), password_hash, salt),
        )
        conexion.commit()
    finally:
        conexion.close()

    return ruta


if __name__ == "__main__":
    # No se imprimen contrasenas ni hashes.
    print("Base de datos creada en:", reiniciar())
    print("Usuario demo:", EMAIL_DEMO)
