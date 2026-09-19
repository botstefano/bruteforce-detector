FROM python:3.11.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # ------------------------------------------------------------------
    # FORTIFICACIÓN CONTRA FALLO "gfortran not found" / sdist build:
    #
    # 1) PIP_ONLY_BINARY → PROHÍBE compilar desde FUENTE (sdist) los 4
    #    paquetes con extensión C/Fortran del proyecto. Si algún wheel
    #    no está disponible para la arquitectura, pip ABORTA con error
    #    claro en lugar de intentar meson + gfortran (que NO existe
    #    en slim y nunca lo instalaremos por peso).
    #
    # 2) PIP_PREFER_BINARY → Para el resto, prefiere wheel si existe.
    #
    # 3) python:3.11-slim = Debian 12 bookworm / glibc 2.36 / x86_64 →
    #    matchea PERFECTAMENTE los wheels manylinux2014 (glibc ≥2.17)
    #    de numpy/scipy/scikit-learn/pandas publicados en PyPI.
    # ------------------------------------------------------------------
    PIP_ONLY_BINARY=numpy,scipy,scikit-learn,pandas \
    PIP_PREFER_BINARY=1 \
    PIP_NO_BINARY=""

WORKDIR /app

# Instala dependencias primero (mejor cacheo de capa)
COPY requirements.txt ./
RUN echo "=== PIP env inside Docker build ===" && \
    python --version && \
    printenv | grep -i PIP || true && \
    pip install --upgrade pip && \
    pip install \
      --no-cache-dir \
      --only-binary=numpy,scipy,scikit-learn,pandas \
      --prefer-binary \
      -r requirements.txt

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

# ------------------------------------------------------------------
# Render inyecta $PORT dinámicamente en runtime (no es 5050 siempre).
# Usamos shell-form + $PORT para escuchar el puerto que Render asigne,
# y sólo caemos a 5050 si PORT no está definido (dev local).
# ------------------------------------------------------------------
CMD gunicorn \
      -k eventlet \
      -w 1 \
      --worker-connections 1000 \
      --timeout 180 \
      --keep-alive 60 \
      --access-logfile - \
      --error-logfile - \
      -b 0.0.0.0:${PORT:-5050} \
      app:app
