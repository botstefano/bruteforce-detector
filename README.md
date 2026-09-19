# Centinela v2 — Microservicio de protección contra fuerza bruta

Segunda versión del prototipo. La diferencia principal frente a la v1:
el detector ya **no vive mezclado con un login de ejemplo** — es un
microservicio independiente que se puede poner delante de **cualquier**
sistema de login (propio o de terceros) con solo dos llamadas HTTP, y
ahora **sí bloquea de verdad**, no solo avisa.

## Arquitectura

```
┌─────────────────────┐         ┌────────────────────────┐
│  demo_login (5000)   │────────▶│  detector_service (5050)│
│  "el login de alguien"│  HTTP   │  Centinela               │
│  Su propia lógica de │◀────────│  Reglas + ML + bloqueo  │
│  autenticación        │         │  Dashboard admin         │
└─────────────────────┘         └────────────────────────┘
        ▲
        │ ataca
┌─────────────────────┐
│  bot_ataque.py         │
└─────────────────────┘
```

- **`detector_service/`** — el microservicio Centinela. Expone los
  endpoints genéricos que cualquier sistema de login puede usar para
  protegerse (`/evaluar`, `/registrar_intento`), más un dashboard de
  administración para monitorear todo, entrenar el modelo ML, y correr
  simulaciones/experimentos.
- **`demo_login/`** — un ejemplo mínimo de "el login de alguien más": tiene
  su propia base de usuarios, su propia lógica de autenticación, **y un
  formulario visual** (`templates/login.html`) donde se puede probar el
  login a mano desde el navegador. Solo agrega dos llamadas HTTP a
  Centinela para protegerse. Sirve como plantilla de integración.
- **`bot_ataque.py`** — bot reutilizable que ataca `demo_login` (no al
  detector directamente), para probar la protección de punta a punta
  como lo haría un atacante real.
- **`experimento.py`** y **`procesar_cicids.py`** — sin cambios de la
  v1, siguen siendo el pipeline para generar las métricas del artículo
  (usan los endpoints de simulación de `detector_service`, no el login
  demo).

## Instalación

```bash
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Cómo correrlo (3 terminales)

**Terminal 1 — Centinela (el detector):**
```bash
cd detector_service
python app.py
```
Dashboard de administración: http://localhost:5050

**Terminal 2 — el login demo:**
```bash
cd demo_login
python app_login_demo.py
```
Abre **http://localhost:5000** en el navegador — vas a ver un formulario
de login real, con usuarios de prueba (`admin/S3guro#2026`,
`carla/MiClave!789`, `roberto/Roberto2026!`). Puedes escribir mal la
contraseña varias veces para ver el bloqueo en acción directamente en
la pantalla, sin necesidad de usar curl ni el bot.

**Terminal 3 — el bot atacante:**
```bash
python bot_ataque.py --tipo rapido
python bot_ataque.py --tipo lento
python bot_ataque.py --tipo distribuido
python bot_ataque.py --tipo rapido --usuario carla --intentos 15
```

Con Centinela y el login demo corriendo, cualquier ataque que lances
con el bot debería, al cabo de pocos intentos, recibir un `HTTP 403`
en vez de `401` — esa es la IP siendo bloqueada de verdad. Puedes
verlo en vivo en el stream del dashboard (http://localhost:5050),
y la sección "Protección en vivo" muestra la IP bloqueada con el
tiempo restante.

## Cómo protegería alguien SU PROPIO login real con esto

El patrón es siempre el mismo, sin importar el lenguaje/framework:

```python
# 1. ANTES de validar la contraseña
resultado = requests.post("http://localhost:5050/evaluar",
                           json={"ip": ip, "usuario": usuario}).json()
if resultado["bloqueado"]:
    return "Demasiados intentos, intenta más tarde", 403

# 2. tu lógica de login de siempre, sin cambios
exitoso = verificar_password(usuario, password)

# 3. DESPUÉS de saber el resultado, avisarle a Centinela
requests.post("http://localhost:5050/registrar_intento",
              json={"ip": ip, "usuario": usuario, "exitoso": exitoso})
```

`demo_login/app_login_demo.py` es exactamente este patrón implementado
en Flask — se puede traducir a Node, PHP, Java, etc. usando cualquier
librería HTTP de ese lenguaje.

## Entrenar el modelo ML con CICIDS2017 (recomendado)

Desde el dashboard (http://localhost:5050), sección "Origen de datos
del modelo ML": escribe la ruta a tu carpeta de CICIDS2017 y presiona
"Entrenar con CICIDS2017". El entrenamiento corre en segundo plano; el
dashboard sigue respondiendo mientras tanto. Al terminar, **todos** los
endpoints (`/evaluar`, `/registrar_intento`, `/login` de prueba, y los
botones de simulación) usan automáticamente el modelo nuevo.

Si no tienes CICIDS2017 a mano, el botón "Volver a sintético" reentrena
con datos generados artificialmente — funciona, pero es menos realista
(ver limitaciones en el artículo).

## Separación importante: tráfico simulado vs. tráfico real

La base de datos distingue dos tipos de eventos:

- **`es_simulado=1`** — generado por los botones del dashboard,
  `experimento.py`, o pruebas contra el login de prueba interno
  (`/login`). Tiene una "verdad fundamental" conocida (tú generaste el
  evento sabiendo si era ataque o no), así que **estos son los únicos
  que se usan para calcular precisión/recall/F1** en `/api/metricas`.
- **`es_simulado=0`** — tráfico real recibido vía `/registrar_intento`
  desde un login externo (como `demo_login`, o el login real de
  alguien). No se sabe con certeza si fue un ataque real o no, así que
  **no contamina las métricas del experimento** — solo se cuenta como
  referencia en `/api/produccion`.

Esto es importante para la validez de las métricas que reportes en el
artículo: mezclar tráfico real sin verdad fundamental con los
experimentos controlados invalidaría la comparación reglas vs. ML.

## Limitaciones a declarar en el artículo

- El bloqueo es **fail-open**: si Centinela no responde (caído, red
  lenta), `demo_login` deja pasar el intento sin bloquear. Es una
  decisión de diseño (disponibilidad del login por encima del bloqueo
  si el detector falla) que debe declararse explícitamente, ya que en
  otros contextos podría preferirse lo contrario (fail-closed).
- La identificación de la IP del atacante depende de la cabecera
  `X-Forwarded-For`. En un despliegue real detrás de un proxy/CDN, solo
  debe confiarse en esa cabecera si el proxy está configurado para
  sobreescribirla correctamente — de lo contrario, es falsificable por
  el propio atacante.
- El modelo ML entrenado con CICIDS2017 traducido sigue siendo una
  aproximación (ver limitaciones ya documentadas en `entrenar_con_cicids.py`).
  Para un despliegue real prolongado, se recomienda reentrenar
  periódicamente con el tráfico histórico propio de cada sitio.
