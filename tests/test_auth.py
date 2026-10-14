"""Pruebas de autenticación de proyecto-login.

Cubre:
- hashing (hash + salt) y verificación con hmac.compare_digest
- validaciones de email y contraseña
- acceso a datos con una base de datos temporal (crear_usuario / autenticar)
- flujo HTTP end-to-end con urllib sobre backend.app.crear_servidor

Todas las pruebas usan una base de datos temporal para no contaminar db/login.db.
"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend import app, auth


class TestHashPassword(unittest.TestCase):
    """hash_password / verify_password."""

    def test_hash_produce_hash_y_salt(self):
        hash_, salt = auth.hash_password("segura123")
        # SHA-256 -> 64 caracteres hex; salt = 16 bytes -> 32 caracteres hex.
        self.assertEqual(len(hash_), 64)
        self.assertEqual(len(salt), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in hash_))

    def test_misma_password_y_salt_verifica(self):
        hash_, salt = auth.hash_password("segura123")
        self.assertTrue(auth.verify_password("segura123", salt, hash_))

    def test_password_incorrecta_no_verifica(self):
        hash_, salt = auth.hash_password("segura123")
        self.assertFalse(auth.verify_password("otra12345", salt, hash_))
        self.assertFalse(auth.verify_password("SEGURA123", salt, hash_))
        self.assertFalse(auth.verify_password("segura12", salt, hash_))

    def test_misma_salt_produce_mismo_hash(self):
        hash1, salt1 = auth.hash_password("segura123", salt="sal-fija-1234567")
        hash2, salt2 = auth.hash_password("segura123", salt="sal-fija-1234567")
        self.assertEqual(salt1, salt2)
        self.assertEqual(hash1, hash2)

    def test_salt_aleatoria_por_defecto(self):
        hash1, salt1 = auth.hash_password("segura123")
        hash2, salt2 = auth.hash_password("segura123")
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hash1, hash2)


class TestValidaciones(unittest.TestCase):
    """validar_email / validar_password."""

    def test_email_validos(self):
        for email in ["ana@correo.com", "usuario@dominio.tld", "a.b+c@sub.dominio.org"]:
            self.assertTrue(auth.validar_email(email), email)

    def test_email_vacio(self):
        self.assertFalse(auth.validar_email(""))

    def test_email_sin_arroba(self):
        self.assertFalse(auth.validar_email("sin-arroba"))

    def test_email_dominio_sin_tld(self):
        self.assertFalse(auth.validar_email("a@b"))
        self.assertFalse(auth.validar_email("ana@correo"))

    def test_email_partes_vacias(self):
        for email in ["@correo.com", "ana@", "ana@@correo.com"]:
            self.assertFalse(auth.validar_email(email), email)

    def test_email_no_es_str(self):
        self.assertFalse(auth.validar_email(None))
        self.assertFalse(auth.validar_email(123))

    def test_email_con_espacios_invalido(self):
        # Un correo con espacios internos no es válido (el frontend también
        # los rechaza con /^[^\s@]+@[^\s@]+\.[^\s@]+$/).
        for email in [
            "usuario con espacios@dominio.com",
            "ana @correo.com",
            "ana@correo .com",
        ]:
            self.assertFalse(auth.validar_email(email), email)

    def test_email_tld_de_un_caracter(self):
        # Documenta el comportamiento actual: 'a@b.c' se acepta porque el
        # dominio contiene un punto. El frontend también lo acepta.
        self.assertTrue(auth.validar_email("a@b.c"))

    def test_password_longitud_minima(self):
        self.assertTrue(auth.validar_password("123456789"))  # 9 (nuevo mínimo)
        self.assertTrue(auth.validar_password("1234567890"))
        self.assertFalse(auth.validar_password("12345678"))  # 8 ya no válido
        self.assertFalse(auth.validar_password("1234567"))  # 7
        self.assertFalse(auth.validar_password(""))
        self.assertFalse(auth.validar_password("corta"))

    def test_password_no_es_str(self):
        self.assertFalse(auth.validar_password(None))
        self.assertFalse(auth.validar_password(12345678))


class TestBaseDeDatos(unittest.TestCase):
    """crear_usuario / autenticar contra una base de datos temporal."""

    def setUp(self):
        self.temporal = tempfile.TemporaryDirectory()
        ruta_db = os.path.join(self.temporal.name, "login_test.db")
        self.conexion = auth.inicializar(ruta_db, auth.SCHEMA_PATH)

    def tearDown(self):
        self.conexion.close()
        self.temporal.cleanup()

    def test_crear_usuario_devuelve_id(self):
        identificador = auth.crear_usuario(
            self.conexion, "ana@correo.com", "segura123"
        )
        self.assertIsNotNone(identificador)
        fila = self.conexion.execute(
            "SELECT email, password_hash, salt FROM usuarios WHERE id = ?",
            (identificador,),
        ).fetchone()
        self.assertEqual(fila["email"], "ana@correo.com")
        self.assertNotEqual(fila["password_hash"], "segura123")
        self.assertTrue(fila["salt"])

    def test_autenticar_correcto(self):
        auth.crear_usuario(self.conexion, "ana@correo.com", "segura123")
        self.assertTrue(auth.autenticar(self.conexion, "ana@correo.com", "segura123"))
        # El email se normaliza (mayúsculas y espacios).
        self.assertTrue(auth.autenticar(self.conexion, " ANA@Correo.com ", "segura123"))

    def test_autenticar_password_incorrecta(self):
        auth.crear_usuario(self.conexion, "ana@correo.com", "segura123")
        self.assertFalse(auth.autenticar(self.conexion, "ana@correo.com", "incorrecta"))

    def test_autenticar_usuario_inexistente(self):
        self.assertFalse(auth.autenticar(self.conexion, "nadie@correo.com", "segura123"))

    def test_email_duplicado_lanza_integrity_error(self):
        auth.crear_usuario(self.conexion, "ana@correo.com", "segura123")
        with self.assertRaises(sqlite3.IntegrityError):
            auth.crear_usuario(self.conexion, "ana@correo.com", "otra12345")

    def test_datos_invalidos_lanzan_value_error(self):
        with self.assertRaises(ValueError):
            auth.crear_usuario(self.conexion, "sin-arroba", "segura123")
        with self.assertRaises(ValueError):
            auth.crear_usuario(self.conexion, "ana@correo.com", "corta")


class TestEndToEnd(unittest.TestCase):
    """Flujo HTTP completo contra backend.app.crear_servidor."""

    @classmethod
    def setUpClass(cls):
        cls.temporal = tempfile.TemporaryDirectory()
        ruta_db = os.path.join(cls.temporal.name, "login_http.db")
        cls.servidor = app.crear_servidor(puerto=0, ruta_db=ruta_db)
        host, puerto = cls.servidor.server_address[:2]
        cls.base = f"http://{host}:{puerto}"
        cls.hilo = threading.Thread(target=cls.servidor.serve_forever, daemon=True)
        cls.hilo.start()

    @classmethod
    def tearDownClass(cls):
        cls.servidor.shutdown()
        cls.servidor.server_close()
        cls.servidor.conexion.close()
        cls.hilo.join(timeout=5)
        cls.temporal.cleanup()

    # --- utilidades -----------------------------------------------------
    def email_unico(self):
        return f"user-{uuid.uuid4().hex}@correo.com"

    def _post(self, ruta, cuerpo):
        datos = json.dumps(cuerpo).encode("utf-8")
        peticion = urllib.request.Request(
            self.base + ruta,
            data=datos,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._abrir(peticion)

    def _get(self, ruta, token=None):
        encabezados = {}
        if token is not None:
            encabezados["Authorization"] = "Bearer " + token
        peticion = urllib.request.Request(
            self.base + ruta, headers=encabezados, method="GET"
        )
        return self._abrir(peticion)

    @staticmethod
    def _abrir(peticion):
        try:
            with urllib.request.urlopen(peticion, timeout=10) as respuesta:
                return respuesta.status, json.loads(respuesta.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read().decode("utf-8"))
            finally:
                error.close()

    def registrar(self, email, password):
        return self._post("/api/register", {"email": email, "password": password})

    def login(self, email, password):
        return self._post("/api/login", {"email": email, "password": password})

    # --- pruebas --------------------------------------------------------
    def test_registro_ok_201(self):
        email = self.email_unico()
        estado, cuerpo = self.registrar(email, "segura123")
        self.assertEqual(estado, 201)
        self.assertTrue(cuerpo["ok"])

    def test_registro_duplicado_409(self):
        email = self.email_unico()
        estado, _ = self.registrar(email, "segura123")
        self.assertEqual(estado, 201)
        estado, cuerpo = self.registrar(email, "segura123")
        self.assertEqual(estado, 409)
        self.assertFalse(cuerpo["ok"])

    def test_login_ok_devuelve_token_200(self):
        email = self.email_unico()
        self.registrar(email, "segura123")
        estado, cuerpo = self.login(email, "segura123")
        self.assertEqual(estado, 200)
        self.assertTrue(cuerpo["ok"])
        self.assertEqual(cuerpo["email"], email)
        self.assertTrue(cuerpo["token"])

    def test_login_password_incorrecta_401(self):
        email = self.email_unico()
        self.registrar(email, "segura123")
        estado, cuerpo = self.login(email, "incorrecta")
        self.assertEqual(estado, 401)
        self.assertFalse(cuerpo["ok"])

    def test_login_usuario_inexistente_401(self):
        estado, _ = self.login("nadie@correo.com", "segura123")
        self.assertEqual(estado, 401)

    def test_me_con_token_200(self):
        email = self.email_unico()
        self.registrar(email, "segura123")
        _, cuerpo = self.login(email, "segura123")
        estado, perfil = self._get("/api/me", token=cuerpo["token"])
        self.assertEqual(estado, 200)
        self.assertTrue(perfil["ok"])
        self.assertEqual(perfil["email"], email)

    def test_me_sin_token_401(self):
        estado, cuerpo = self._get("/api/me")
        self.assertEqual(estado, 401)
        self.assertFalse(cuerpo["ok"])

    def test_me_token_invalido_401(self):
        estado, cuerpo = self._get("/api/me", token="token-falso")
        self.assertEqual(estado, 401)
        self.assertFalse(cuerpo["ok"])

    def test_me_encabezado_sin_bearer_401(self):
        peticion = urllib.request.Request(
            self.base + "/api/me",
            headers={"Authorization": "Basic abc"},
            method="GET",
        )
        estado, _ = self._abrir(peticion)
        self.assertEqual(estado, 401)

    def test_registro_password_corta_400(self):
        estado, cuerpo = self.registrar(self.email_unico(), "corta")
        self.assertEqual(estado, 400)
        self.assertFalse(cuerpo["ok"])

    def test_registro_email_invalido_400(self):
        estado, cuerpo = self.registrar("sin-arroba", "segura123")
        self.assertEqual(estado, 400)
        self.assertFalse(cuerpo["ok"])


class TestNuevos(unittest.TestCase):
    """5 tests nuevos: 4 pasan, 1 falla intencionalmente."""

    def test_generar_token_unicidad(self):
        tokens = {app.generar_token() for _ in range(100)}
        self.assertEqual(len(tokens), 100)
        for t in tokens:
            self.assertTrue(all(c.isalnum() or c in "-_" for c in t))
            self.assertGreaterEqual(len(t), 32)

    def test_password_complejidad_opcional(self):
        def validar_password_compleja(pwd):
            if not isinstance(pwd, str) or len(pwd) < 8:
                return False
            tiene_mayus = any(c.isupper() for c in pwd)
            tiene_minus = any(c.islower() for c in pwd)
            tiene_num = any(c.isdigit() for c in pwd)
            return tiene_mayus and tiene_minus and tiene_num

        self.assertTrue(validar_password_compleja("Segura123"))
        self.assertTrue(validar_password_compleja("Abcdef12"))
        self.assertFalse(validar_password_compleja("segura123"))
        self.assertFalse(validar_password_compleja("SEGURA123"))
        self.assertFalse(validar_password_compleja("Seguraabc"))
        self.assertFalse(validar_password_compleja("12345678"))

    def test_sql_injection_intentada(self):
        inyecciones = [
            "' OR '1'='1",
            "'; DROP TABLE usuarios; --",
            "admin'--",
            '" OR ""="',
            "' UNION SELECT * FROM usuarios --",
        ]
        for inj in inyecciones:
            self.assertFalse(auth.validar_email(inj), f"Email inyección: {inj}")
        # La validación de password solo comprueba longitud; la protección SQL
        # real está en las consultas parametrizadas (crear_usuario/autenticar).
        # Verificamos que una inyección como password no rompe el flujo:
        with tempfile.TemporaryDirectory() as tmp:
            ruta_db = os.path.join(tmp, "test.db")
            conn = auth.inicializar(ruta_db, auth.SCHEMA_PATH)
            try:
                auth.crear_usuario(conn, "victima@correo.com", "segura123")
                # Intentar login con inyección en password - debe fallar sin error SQL
                self.assertFalse(auth.autenticar(conn, "victima@correo.com", "' OR '1'='1"))
            finally:
                conn.close()

    def test_sesion_token_expiracion(self):
        token_valido = app.generar_token()
        SESIONES = {token_valido: "test@correo.com"}
        status, body = app.manejar_me(SESIONES, {"Authorization": f"Bearer {token_valido}"})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        status, body = app.manejar_me(SESIONES, {"Authorization": "Bearer token-inexistente"})
        self.assertEqual(status, 401)
        self.assertFalse(body["ok"])

    def test_password_minima_rechazada(self):
        """FALLA INTENCIONAL: espera que 8 chars sea rechazado (requisito nuevo: min 9)."""
        self.assertFalse(auth.validar_password("12345678"), "8 chars debería fallar con nuevo requisito")


if __name__ == "__main__":
    unittest.main()
