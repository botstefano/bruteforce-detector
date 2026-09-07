"""
detector_ml.py
Detector de fuerza bruta basado en comportamiento, usando
Isolation Forest sobre una ventana deslizante de features por IP.

Features usadas (calculadas por IP en una ventana de tiempo):
- num_intentos: cantidad de intentos fallidos recientes
- num_usuarios_distintos: cuántos usuarios distintos probó esa IP
- intervalo_promedio: tiempo promedio entre intentos consecutivos
- intervalo_std: desviación estándar del intervalo (los bots son
  muy regulares; los humanos, irregulares)
- hora_del_dia: hora en que ocurre (0-23), como señal débil
"""
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest
import time
import datetime


class DetectorML:
    def __init__(self, ventana_features=120, contamination=0.15):
        self.ventana_features = ventana_features
        self.contamination = contamination
        self.modelo = None
        self.entrenado = False

        self.intentos_por_ip = defaultdict(deque)  # (timestamp, usuario)

    def _limpiar(self, cola, ahora):
        while cola and ahora - cola[0][0] > self.ventana_features:
            cola.popleft()

    def _extraer_features(self, ip, ahora):
        cola = self.intentos_por_ip[ip]
        self._limpiar(cola, ahora)
        timestamps = [t for t, _ in cola]
        usuarios = {u for _, u in cola}

        num_intentos = len(timestamps)
        num_usuarios = len(usuarios)

        if num_intentos >= 2:
            intervalos = np.diff(sorted(timestamps))
            intervalo_promedio = float(np.mean(intervalos))
            intervalo_std = float(np.std(intervalos))
        else:
            intervalo_promedio = self.ventana_features
            intervalo_std = 0.0

        hora = datetime.datetime.fromtimestamp(ahora).hour

        return [num_intentos, num_usuarios, intervalo_promedio,
                intervalo_std, hora]

    def entrenar_con_datos_normales(self, muestras_normales):
        """muestras_normales: lista de vectores de features
        representativos de tráfico legítimo, usada para calibrar
        el modelo antes de operar en línea."""
        X = np.array(muestras_normales)
        self.modelo = IsolationForest(
            n_estimators=150,
            contamination=self.contamination,
            random_state=42,
        )
        self.modelo.fit(X)
        self.entrenado = True

    def registrar_y_evaluar(self, ip, usuario, exitoso, timestamp=None):
        ahora = timestamp if timestamp is not None else time.time()

        if not exitoso:
            self.intentos_por_ip[ip].append((ahora, usuario))

        features = self._extraer_features(ip, ahora)

        if not self.entrenado:
            return {"alerta": False, "score": 0.0, "features": features}

        pred = self.modelo.predict([features])[0]  # -1 anomalía, 1 normal
        score = float(self.modelo.decision_function([features])[0])

        return {
            "alerta": pred == -1,
            "score": round(score, 4),
            "features": features,
        }

    def reset(self):
        self.intentos_por_ip.clear()


def generar_muestras_normales(n=300, semilla=42, ventana_features=120):
    """Genera vectores de features sintéticos representando
    comportamiento de login LEGÍTIMO (usuarios humanos): pocos
    intentos, intervalos irregulares y largos, horario laboral.

    Replica exactamente la lógica de _extraer_features para que el
    modelo generalice bien al caso de 0 o 1 intentos fallidos, que
    es el escenario más común de tráfico legítimo."""
    rng = np.random.default_rng(semilla)
    muestras = []
    for _ in range(n):
        num_intentos = rng.integers(0, 3)          # humanos fallan poco
        num_usuarios = 1 if num_intentos > 0 else 0

        if num_intentos >= 2:
            intervalo_prom = rng.uniform(20, 120)   # tardan en reintentar
            intervalo_std = rng.uniform(5, 40)       # irregular
        else:
            # mismo valor por defecto que usa el extractor real
            # cuando hay menos de 2 intentos en la ventana
            intervalo_prom = ventana_features
            intervalo_std = 0.0

        hora = rng.integers(7, 22)                  # horario humano típico
        muestras.append([num_intentos, num_usuarios, intervalo_prom,
                          intervalo_std, hora])
    return muestras
