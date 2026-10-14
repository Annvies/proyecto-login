# proyecto-login

Login mínimo y funcional con **backend + frontend + base de datos**, usando solo la
librería estándar de Python y SQLite. No requiere instalar dependencias.

## Estructura

```
proyecto-login/
├── backend/
│   ├── auth.py        # hashing (pbkdf2), validaciones y acceso a datos
│   └── app.py         # servidor HTTP: API + archivos estáticos
├── db/
│   ├── schema.sql     # tabla usuarios
│   └── init_db.py     # crea login.db y el usuario demo
├── frontend/
│   ├── index.html     # formulario de login/registro
│   ├── styles.css
│   └── app.js         # fetch contra la API
├── tests/
│   └── test_auth.py   # unittest + flujo E2E por HTTP
└── README.md
```

## Cómo ejecutar

Desde la carpeta `proyecto-login/`:

```bash
python -m db.init_db        # crea la base y el usuario demo
python -m backend.app       # servidor en http://127.0.0.1:8000
```

Abre `http://127.0.0.1:8000` en el navegador.

Usuario demo: `demo@login.com` / `demo1234`.

## Pruebas

```bash
python -m unittest discover -s tests -v
```

Cubren validaciones, hashing (con sal aleatoria) y el flujo completo
registro → login por HTTP.

## API

| Método | Ruta | Cuerpo | Respuesta ok | Error |
| --- | --- | --- | --- | --- |
| POST | `/api/register` | `{"email","password"}` | `201 {"ok":true}` | `400` inválido, `409` duplicado |
| POST | `/api/login` | `{"email","password"}` | `200 {"ok":true,"email","token"}` | `401` credenciales |
| GET | `/api/me` | header `Authorization: Bearer <token>` | `200 {"ok":true,"email"}` | `401` |

## Seguridad

- Las contraseñas se guardan con `hashlib.pbkdf2_hmac` (SHA-256, 120 000 iteraciones)
  y una sal única por usuario generada con `secrets`.
- La comparación de hashes usa `hmac.compare_digest` (tiempo constante).
- Las consultas SQL son parametrizadas.

## Creado con

La skill **`crear-login`** y sus subagentes `disenador-datos`, `backend-login`,
`frontend-login` y `verificador-login` (en `.opencode/`).
