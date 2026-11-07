# Práctica de Seguridad MTTD y MTTR

Aplicación local de Flask y SQLite para registrar usuarios e incidentes, proteger
las contraseñas con hash, guardar eventos de inicio de sesión y medir MTTD/MTTR.

## Ubicación

La aplicación está en la carpeta raíz del proyecto. Abre esa carpeta en VS
Code; la aplicación se ejecuta localmente y se abre en el navegador.

## Requisitos

- Python 3.9 o posterior. Si no está instalado, instala Python desde
  <https://www.python.org/downloads/windows/> y marca **Add Python to PATH**.
- Flask: se instala en los siguientes pasos.

## Ejecución en Windows (PowerShell)

En VS Code, abre **Terminal > Nueva terminal** y ejecuta estos comandos:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:FLASK_SECRET_KEY = (.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")
.\.venv\Scripts\python.exe app.py
```

Si `py` no se reconoce, verifica que Python esté instalado y abre una terminal
nueva; también puedes sustituir `py -3` por `python` si ese comando está
disponible.

Cuando la terminal muestre que Flask está ejecutándose, abre
<http://127.0.0.1:5000> en tu navegador y crea una cuenta. Deja abierta la
terminal mientras utilizas la aplicación; para detenerla, presiona `Ctrl+C`.
Para probar la alerta, falla tres veces seguidas el inicio de sesión con el
mismo usuario. El tercer fallo genera el incidente y bloquea esa cuenta
temporalmente.

## Funcionalidad

- Validación de nombre de usuario, correo, contraseña e incidentes.
- Consultas SQLite parametrizadas y restricciones únicas para usuarios/correos.
- Hash de contraseñas; protección CSRF en formularios y cookies de sesión
  `HttpOnly`/`SameSite`.
- Registro de inicios correctos y fallidos en SQLite y `instance/eventos.log`.
- Detección de tres fallos en una ventana de 15 minutos, alerta y bloqueo por
  15 minutos.
- Registro de incidentes y acciones de respuesta.
- Cálculo de MTTD (inicio a detección), MTTR (detección a respuesta) y sus
  promedios en el panel.

Los archivos `instance/security.db` y `instance/eventos.log` se crean al
ejecutar la aplicación y no deben subirse al repositorio. Todas las fechas se
guardan en UTC.

## Pruebas

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
