FROM python:3.11.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Instala dependencias primero (mejor cacheo de capa)
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Código fuente (detector_service + bot_ataque.py etc.)
COPY . .

# Asegura directorios de persistencia
RUN mkdir -p /app/detector_service/data /data

WORKDIR /app/detector_service

# DB por defecto en /data (montar volumen en producción para persistencia)
ENV DB_PATH=/data/centinela_eventos.db \
    FLASK_ENV=production \
    SOCKETIO_ASYNC_MODE=eventlet

EXPOSE 5050

# 1 worker IMPRESCINDIBLE para Socket.IO (sin pub/sub Redis).
# Eventlet + 1000 conexiones por worker.
CMD ["gunicorn", "-k", "eventlet", "-w", "1", \
     "--worker-connections", "1000", \
     "--timeout", "180", \
     "--keep-alive", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "-b", "0.0.0.0:5050", \
     "app:app"]
