"""
experimento.py
Automatiza la ejecución repetida de cada escenario de ataque contra el
prototipo (app.py debe estar corriendo en paralelo) y guarda las métricas
resultantes en un CSV, listo para analizar en pandas/Excel y usar en el
artículo.

USO:
    1. En una terminal:  python app.py
    2. En otra terminal: python experimento.py

Requiere la librería 'requests' (no viene en requirements.txt original):
    pip install requests
"""
import csv
import time
import requests
from datetime import datetime

BASE_URL = "http://127.0.0.1:5050"
SALIDA_CSV = "resultados_experimento.csv"

# Repeticiones por escenario. Ajusta según el tiempo que tengas disponible;
# 15-20 es un mínimo razonable para poder reportar promedio y desviación
# estándar en el artículo.
REPETICIONES = 15

# Tiempo de espera (segundos) tras lanzar cada escenario, antes de leer
# las métricas. Debe ser mayor a la duración real del escenario en app.py.
ESPERA = {
    "rapido": 5,
    "lento": 25,
    "distribuido": 3,
    "legitimo": 25,
    "mixto": 25,
}


def resetear():
    requests.post(f"{BASE_URL}/reset")
    time.sleep(0.5)


def leer_metricas():
    r = requests.get(f"{BASE_URL}/api/metricas")
    return r.json()


def lanzar_ataque(tipo):
    requests.post(f"{BASE_URL}/simular/ataque", json={"tipo": tipo})


def lanzar_legitimo(cantidad=10):
    requests.post(f"{BASE_URL}/simular/legitimo", json={"cantidad": cantidad})


def correr_escenario(nombre):
    """Ejecuta un escenario y devuelve las métricas al finalizar."""
    resetear()

    if nombre == "legitimo":
        lanzar_legitimo(cantidad=10)
    elif nombre == "mixto":
        # ataque + tráfico legítimo intercalado, para simular condiciones
        # más realistas donde el sistema no sabe de antemano qué es qué
        lanzar_legitimo(cantidad=6)
        time.sleep(1)
        lanzar_ataque("rapido")
    else:
        lanzar_ataque(nombre)

    time.sleep(ESPERA[nombre])
    return leer_metricas()


def fila_desde_metricas(escenario, repeticion, metricas):
    if metricas is None:
        # puede pasar si un escenario no generó ningún evento
        return None
    r = metricas["alerta_reglas"]
    m = metricas["alerta_ml"]
    return {
        "escenario": escenario,
        "repeticion": repeticion,
        "total_intentos": metricas["total_intentos"],
        "precision_reglas": r["precision"],
        "recall_reglas": r["recall"],
        "f1_reglas": r["f1"],
        "fp_reglas": r["falsos_positivos"],
        "fn_reglas": r["falsos_negativos"],
        "precision_ml": m["precision"],
        "recall_ml": m["recall"],
        "f1_ml": m["f1"],
        "fp_ml": m["falsos_positivos"],
        "fn_ml": m["falsos_negativos"],
    }


def main():
    escenarios = ["rapido", "lento", "distribuido", "legitimo", "mixto"]
    filas = []

    total_corridas = len(escenarios) * REPETICIONES
    corrida_actual = 0

    print(f"Iniciando experimento: {len(escenarios)} escenarios x "
          f"{REPETICIONES} repeticiones = {total_corridas} corridas")
    print(f"Hora de inicio: {datetime.now().strftime('%H:%M:%S')}\n")

    for escenario in escenarios:
        for rep in range(1, REPETICIONES + 1):
            corrida_actual += 1
            print(f"[{corrida_actual}/{total_corridas}] "
                  f"escenario={escenario} repetición={rep}...", end=" ", flush=True)

            try:
                metricas = correr_escenario(escenario)
                fila = fila_desde_metricas(escenario, rep, metricas)
                if fila:
                    filas.append(fila)
                    print(f"OK (F1 reglas={fila['f1_reglas']}, F1 ml={fila['f1_ml']})")
                else:
                    print("SIN EVENTOS (omitido)")
            except requests.exceptions.ConnectionError:
                print("\nERROR: no se pudo conectar a "
                      f"{BASE_URL}. ¿Está corriendo 'python app.py'?")
                return

    if not filas:
        print("\nNo se generó ninguna fila de resultados. Revisa que el "
              "servidor esté corriendo y que los tiempos de ESPERA sean suficientes.")
        return

    with open(SALIDA_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=filas[0].keys())
        writer.writeheader()
        writer.writerows(filas)

    print(f"\nListo. Resultados guardados en: {SALIDA_CSV}")
    print(f"Hora de fin: {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()
