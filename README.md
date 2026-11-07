# Práctica de Seguridad: MTTD y MTTR

**Estudiante:** Jonathan Alexander González Juárez

**Asignatura:** Lenguajes de Programación con Aspectos de Seguridad

**Práctica:** MTTD y MTTR

## Descripción

Aplicación web desarrollada con Python, Flask y SQLite para gestionar usuarios,
registrar eventos de autenticación, detectar intentos fallidos y calcular las
métricas MTTD y MTTR.

## Estructura del proyecto

```text
app.py
detector.py
requirements.txt
.gitignore
templates/
  base.html
  dashboard.html
  login.html
  register.html
tests/
  test_app.py
```

Al ejecutarse, la aplicación crea la base de datos y los registros de eventos
en `instance/`. Son archivos locales generados y no se suben al repositorio.

## Ejecución en Windows

Desde la carpeta del proyecto, abre una terminal de PowerShell y ejecuta:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:FLASK_SECRET_KEY = (.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")
.\.venv\Scripts\python.exe app.py
```

Abre <http://127.0.0.1:5000> en el navegador.
