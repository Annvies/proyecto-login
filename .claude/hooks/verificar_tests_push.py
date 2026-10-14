#!/usr/bin/env python3
"""Hook pre-push: verifica tests y sugiere fix para test_password_minima_rechazada.

Si solo falla el test intencional, ofrece dos opciones de fix:
  A) Modificar test (aceptar 8 chars como válido - comportamiento actual)
  B) Modificar código (cambiar LONGITUD_MINIMA = 9 en auth.py)

Bloquea el push (exit 2) para que el usuario decida y aplique el fix.
"""
import re
import subprocess
import sys

TEST_INTENCIONAL = "test_password_minima_rechazada"
TEST_CLASS = "TestNuevos"


def es_push_git(comando: str) -> bool:
    """Detecta si el comando es git push (incluye git.exe, opciones globales)."""
    return bool(re.search(r"\bgit(?:\.exe)?\b[^\r\n;&|]*\bpush\b", comando, re.IGNORECASE))


def correr_tests():
    """Ejecuta todos los tests y devuelve (returncode, stdout, stderr)."""
    try:
        resultado = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        return resultado.returncode, resultado.stdout, resultado.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"PUSH BLOQUEADO: no se pudieron verificar las pruebas: {e}", file=sys.stderr)
        sys.exit(2)


def analizar_fallos(stdout: str, stderr: str):
    """Analiza la salida y devuelve lista de tests fallidos."""
    salida = stdout + stderr
    fallos = []

    # Busca patrones como: FAIL: test_name (module.Class.test_name)
    # El formato es: FAIL: test_password_minima_rechazada (test_auth.TestNuevos.test_password_minima_rechazada)
    patron = re.compile(r"^FAIL:\s+(\w+)\s+\(([^)]+\.(\w+)\.\w+)\)", re.MULTILINE)
    for match in patron.finditer(salida):
        test_name = match.group(1)
        class_name = match.group(3)  # Captura el nombre de la clase (TestNuevos)
        fallos.append((test_name, class_name))

    return fallos


def sugerir_fixes():
    """Imprime instrucciones de fix para el test intencional."""
    print("\n" + "=" * 70, file=sys.stderr)
    print("⚠️  TEST INTENCIONALMENTE FALLIDO DETECTADO", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"\nEl test '{TEST_INTENCIONAL}' falla como se esperaba.", file=sys.stderr)
    print("Simula un nuevo requisito: contraseña mínima de 9 caracteres (actual: 8).", file=sys.stderr)
    print("\n🔧 DOS OPCIONES PARA SOLUCIONARLO:", file=sys.stderr)
    print("-" * 70, file=sys.stderr)
    print("OPCIÓN A: Modificar el TEST (aceptar comportamiento actual: 8 chars OK)", file=sys.stderr)
    print("  → Edita tests/test_auth.py", file=sys.stderr)
    print("  → Cambia la aserción en test_password_minima_rechazada:", file=sys.stderr)
    print('      self.assertTrue(auth.validar_password("12345678"))  # era assertFalse', file=sys.stderr)
    print("  → O elimina/comenta el test si ya no aplica", file=sys.stderr)
    print("\nOPCIÓN B: Modificar el CÓDIGO (implementar nuevo requisito: min 9 chars)", file=sys.stderr)
    print("  → Edita backend/auth.py", file=sys.stderr)
    print("  → Cambia LONGITUD_MINIMA = 8  por  LONGITUD_MINIMA = 9", file=sys.stderr)
    print("  → El test pasará automáticamente", file=sys.stderr)
    print("-" * 70, file=sys.stderr)
    print("\n📝 PASOS:", file=sys.stderr)
    print("  1. Elige A o B y aplica el cambio", file=sys.stderr)
    print("  2. git add -A && git commit --amend --no-edit  (o nuevo commit)", file=sys.stderr)
    print("  3. git push origin develop  (los tests pasarán y el push se permitirá)", file=sys.stderr)
    print("=" * 70 + "\n", file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        print("Uso: python verificar_tests_push.py '<comando>'", file=sys.stderr)
        sys.exit(1)

    comando = " ".join(sys.argv[1:])

    if not es_push_git(comando):
        return  # No es un push, no hacemos nada

    print("🔍 Hook pre-push: ejecutando tests...", file=sys.stderr)

    returncode, stdout, stderr = correr_tests()

    if returncode == 0:
        # Buscar confirmación de tests ejecutados
        if re.search(r"Ran \d+ tests?", stdout):
            print("✅ Hook pre-push: todos los tests pasaron; push permitido.", file=sys.stderr)
            sys.exit(0)
        else:
            print("⚠️ Hook pre-push: no se detectaron tests ejecutados.", file=sys.stderr)
            sys.exit(0)

    # Hubo fallos
    fallos = analizar_fallos(stdout, stderr)

    # Verificar si SOLO falla el test intencional
    solo_intencional = (
        len(fallos) == 1
        and fallos[0][0] == TEST_INTENCIONAL
        and fallos[0][1] == TEST_CLASS
    )

    if solo_intencional:
        sugerir_fixes()
        print("🚫 PUSH BLOQUEADO: aplica uno de los fixes arriba y reintenta.", file=sys.stderr)
        sys.exit(2)

    # Otros fallos inesperados
    print("🚫 PUSH BLOQUEADO: tests fallaron inesperadamente.", file=sys.stderr)
    print("\nFallos detectados:", file=sys.stderr)
    for test, cls in fallos:
        print(f"  - {cls}.{test}", file=sys.stderr)
    print("\nCorrige el código (sin modificar tests intencionales) y reintenta.", file=sys.stderr)
    print("\n--- Salida de tests (últimas 80 líneas) ---", file=sys.stderr)
    salida = (stdout + stderr).splitlines()
    for linea in salida[-80:]:
        print(linea, file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()