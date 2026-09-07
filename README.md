# Centinela — Prototipo de detección de fuerza bruta en tiempo real

Prototipo desarrollado como base experimental para el artículo *"Detección de
ataques de fuerza bruta en tiempo real: comparación entre reglas adaptativas
y aprendizaje automático"*.

Implementa y compara dos enfoques de detección sobre un mismo flujo de
intentos de login simulado:

1. **Reglas adaptativas**: extiende el enfoque clásico tipo *fail2ban* con
   detección de ataques distribuidos (multi-IP contra el mismo usuario) y
   ataques lentos (*low-and-slow*).
2. **Machine Learning (Isolation Forest)**: detecta anomalías de
   comportamiento (frecuencia, regularidad de intervalos, diversidad de
   usuarios probados) sin depender de umbrales fijos.

Ambos detectores procesan cada intento en paralelo, lo que permite comparar
precisión, recall y F1 de forma directa y reproducible — el aporte empírico
central del artículo.

## Estructura del proyecto

```
bruteforce-detector/
├── app.py                 # Servidor Flask + WebSockets + orquestación
├── database.py             # Persistencia SQLite y cálculo de métricas
├── detector_reglas.py       # Detector basado en reglas adaptativas
├── detector_ml.py            # Detector basado en Isolation Forest
├── templates/
│   └── dashboard.html         # Dashboard en tiempo real
├── data/
│   └── eventos.db               # Base de datos (se genera al ejecutar)
└── requirements.txt
```

## Instalación

```bash
cd bruteforce-detector
python3 -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Ejecución

```bash
python app.py
```

Abre el navegador en **http://localhost:5050**

## Uso del dashboard

El panel de control permite generar tráfico sin necesidad de herramientas
externas (Hydra, scripts adicionales, etc.):

- **Ataque rápido**: ráfaga de ~10 intentos desde una sola IP en pocos
  segundos (equivalente a lo que detectaría fail2ban).
- **Ataque lento**: intentos espaciados varios segundos, diseñados para
  evadir umbrales simples de ráfaga.
- **Ataque distribuido**: varias IPs distintas probando el mismo usuario en
  paralelo (simula una botnet).
- **Generar tráfico legítimo**: logins simulando comportamiento humano
  (usado para medir falsos positivos).
- **Reiniciar estado**: limpia la base de datos y el historial en memoria de
  ambos detectores, para correr un nuevo experimento desde cero.

Cada intento se transmite en vivo por WebSocket y aparece en el stream con
las banderas `REGLAS` y/o `ML` si alguno de los detectores lo marcó como
sospechoso. El panel derecho recalcula precisión, recall y F1 en tiempo real
comparando contra la verdad fundamental de cada intento (si fue parte de un
ataque simulado o de tráfico legítimo).

## Endpoint de login real

`POST /login` con body `{"usuario": "...", "password": "..."}` pasa por el
mismo pipeline de detección que los eventos simulados y responde:

- `200` si las credenciales son correctas y no hay alertas
- `401` si las credenciales son incorrectas
- `429` si el request fue bloqueado por alguno de los detectores

Esto permite, si se desea extender el prototipo, conectarlo a un formulario
de login real en lugar de solo simulaciones.

## Cómo usar esto en el artículo

1. Corre varias rondas de cada tipo de ataque (rápido, lento, distribuido)
   junto con tráfico legítimo intercalado.
2. Registra las métricas de `/api/metricas` después de cada ronda (o expórtalas
   con `GET /api/eventos`, que devuelve el detalle en JSON).
3. Arma una tabla comparativa reglas vs. ML por tipo de ataque — este es tu
   principal resultado empírico.
4. Discute los casos donde cada enfoque falla: las reglas tienden a fallar
   en ataques lentos con umbrales mal calibrados; el modelo ML puede generar
   falsos positivos con usuarios que fallan el login más de una vez en poco
   tiempo (un caso real y legítimo, útil para discutir en la sección de
   limitaciones).

## Limitaciones a mencionar en el artículo

- El modelo Isolation Forest se entrena con datos sintéticos de tráfico
  "normal", no con logs reales de producción — es un punto de partida, no
  un modelo listo para producción.
- Las métricas dependen del escenario simulado; para reforzar la validez
  externa del estudio, se recomienda complementar estos resultados con el
  dataset CICIDS2017 (tráfico de fuerza bruta SSH/FTP ya etiquetado).
- El detector distribuido asume que el atacante repite el mismo usuario
  objetivo; ataques que rotan usuarios y contraseñas de forma aleatoria
  entre IPs requerirían una feature adicional (similitud de patrones entre
  IPs no coordinadas explícitamente).
