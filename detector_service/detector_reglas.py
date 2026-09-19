"""
detector_reglas.py
Detector de fuerza bruta basado en reglas adaptativas.

A diferencia de un enfoque estático tipo fail2ban (umbral fijo de
intentos por IP en una ventana fija), este detector añade dos
mejoras pensadas para cubrir los vacíos identificados en la revisión
de literatura:

1. Detección de ataques DISTRIBUIDOS: agrupa intentos por el patrón
   de usuario/contraseña probado, no solo por IP, para detectar
   varias IPs coordinadas atacando la misma cuenta.
2. Detección de ataques LENTOS (low-and-slow): usa una ventana larga
   además de la corta, para IPs que evitan el umbral clásico
   repartiendo sus intentos en el tiempo.
"""
from collections import defaultdict, deque
import time


class DetectorReglas:
    def __init__(self,
                 umbral_rapido=5, ventana_rapida=60,
                 umbral_lento=8, ventana_lenta=900,
                 umbral_distribuido_ips=4, ventana_distribuida=120):
        self.umbral_rapido = umbral_rapido
        self.ventana_rapida = ventana_rapida
        self.umbral_lento = umbral_lento
        self.ventana_lenta = ventana_lenta
        self.umbral_distribuido_ips = umbral_distribuido_ips
        self.ventana_distribuida = ventana_distribuida

        # historial de timestamps de intentos fallidos por IP
        self.intentos_por_ip = defaultdict(deque)
        # historial de (ip, timestamp) por usuario objetivo, para
        # detectar ataques distribuidos contra la misma cuenta
        self.intentos_por_usuario = defaultdict(deque)

    def _limpiar_ventana(self, cola, ahora, ventana):
        while cola and ahora - cola[0][0] > ventana:
            cola.popleft()

    def evaluar(self, ip, usuario, exitoso, timestamp=None):
        """Devuelve un dict con el veredicto y la razón de la regla
        disparada (o None si no hay alerta)."""
        ahora = timestamp if timestamp is not None else time.time()

        if exitoso:
            # un login exitoso no se descarta del historial: podría
            # ser el resultado final de un ataque exitoso, pero no
            # dispara alertas por sí mismo.
            return {"alerta": False, "razon": None}

        # --- registrar el intento fallido ---
        self.intentos_por_ip[ip].append((ahora, usuario))
        self.intentos_por_usuario[usuario].append((ahora, ip))

        # --- regla 1: ráfaga rápida por IP (equivalente a fail2ban) ---
        cola_ip = self.intentos_por_ip[ip]
        self._limpiar_ventana(cola_ip, ahora, self.ventana_lenta)
        recientes_rapidos = [t for t, _ in cola_ip if ahora - t <= self.ventana_rapida]
        if len(recientes_rapidos) >= self.umbral_rapido:
            return {"alerta": True,
                    "razon": f"ráfaga rápida: {len(recientes_rapidos)} intentos "
                              f"desde {ip} en {self.ventana_rapida}s"}

        # --- regla 2: ataque lento (low-and-slow) por IP ---
        if len(cola_ip) >= self.umbral_lento:
            return {"alerta": True,
                    "razon": f"ataque lento: {len(cola_ip)} intentos "
                              f"desde {ip} en {self.ventana_lenta}s"}

        # --- regla 3: ataque distribuido contra el mismo usuario ---
        cola_usuario = self.intentos_por_usuario[usuario]
        self._limpiar_ventana(cola_usuario, ahora, self.ventana_distribuida)
        ips_distintas = {ip_ for _, ip_ in cola_usuario}
        if len(ips_distintas) >= self.umbral_distribuido_ips:
            return {"alerta": True,
                    "razon": f"ataque distribuido: {len(ips_distintas)} IPs distintas "
                              f"probando el usuario '{usuario}' en "
                              f"{self.ventana_distribuida}s"}

        return {"alerta": False, "razon": None}

    def reset(self):
        self.intentos_por_ip.clear()
        self.intentos_por_usuario.clear()
