#!/usr/bin/env python3
"""
experimento.py — Pipeline de Experimentación Automatizado para Centinela

Este script ejecuta de manera controlada los experimentos de validación
para la comparativa científica entre Reglas WAF y Modelos de ML
(Isolation Forest, One-Class SVM, Local Outlier Factor y Ensamble).

Genera:
1. Tráfico legítimo de control (ground truth = benigno)
2. Ataques de ráfaga rápida (fuerza bruta clásica)
3. Ataques low-and-slow (ataque sigiloso)
4. Ataques distribuidos (botnet / rotación de IPs)
5. Descarga y exportación del dataset consolidado (CSV)
6. Tabla comparativa de métricas (Precisión, Recall, F1-Score)
"""

import sys
import time
import json
import argparse
import urllib.request
import urllib.error

DEFAULT_URL = "http://localhost:3000"

def peticion(url_base, path, metodo="GET", data=None):
    url = f"{url_base}{path}"
    req = urllib.request.Request(url, method=metodo)
    req.add_header("User-Agent", "Centinela-Experimentador/2.0")
    if data is not None:
        req.add_header("Content-Type", "application/json")
        cuerpo = json.dumps(data).encode("utf-8")
    else:
        cuerpo = None

    try:
        with urllib.request.urlopen(req, data=cuerpo, timeout=30) as resp:
            contenido = resp.read().decode("utf-8")
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return json.loads(contenido)
            return contenido
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode("utf-8", errors="ignore")
        try:
            return json.loads(error_msg)
        except Exception:
            return {"error": f"HTTP {e.code}: {error_msg}"}
    except Exception as e:
        return {"error": str(e)}

def ejecutar_experimento(url_base, resetear=True, cantidad=1000):
    print("=" * 65)
    print(" CENTINELA — PROTOCOLO EXPERIMENTAL DE VALIDACIÓN CIENTÍFICA")
    print(f" Servidor objetivo: {url_base} | Muestra solicitada: N = {cantidad}")
    print("=" * 65)

    # 1. Comprobar salud del servidor
    print("\n[1/5] Verificando disponibilidad de Centinela...")
    health = peticion(url_base, "/health")
    if "status" not in health or health.get("status") != "ok":
        print(f"❌ Error al conectar con {url_base}: {health}")
        sys.exit(1)
    print(f"  ✓ Servicio activo ({health.get('service')}), DB OK: {health.get('db_ok')}")

    # 2. Resetear estado si se solicita
    if resetear:
        print("\n[2/5] Reiniciando base de datos y memoria para el experimento...")
        res = peticion(url_base, "/reset", metodo="POST")
        print("  ✓ Estado reiniciado a cero.")

    # 3. Inyectar benchmark masivo con balance estadístico
    print(f"\n[3/5] Inyectando Benchmark Masivo (N = {cantidad} eventos)...")
    print("  -> Distribución: 50% Control Benigno, 20% Ráfaga, 15% Low-and-Slow, 15% Botnet Distribuida")
    bench = peticion(url_base, "/simular/benchmark_masivo", metodo="POST", data={"cantidad": cantidad})
    if bench.get("status") == "ok":
        d = bench.get("desglose", {})
        print(f"  ✓ Generados exitosamente: {bench.get('total_generados')} eventos.")
        print(f"    - Legítimos: {d.get('legitimo')} | Ráfaga: {d.get('ataque_rapido')} | Lento: {d.get('ataque_lento')} | Distribuido: {d.get('ataque_distribuido')}")
    else:
        print(f"  ⚠️ Error al generar benchmark: {bench}")

    # 4. Obtener métricas consolidadas
    print("\n[4/5] Extrayendo métricas estadísticas consolidadas...")
    metricas = peticion(url_base, "/api/metricas")
    
    if not metricas or "total_intentos" not in metricas:
        print("  ⚠️ No se obtuvieron métricas suficientes aún.")
    else:
        print(f"  ✓ Total de eventos de prueba evaluados: {metricas.get('total_intentos')}\n")
        
        # Tabla comparativa formateada para el artículo
        print("-" * 75)
        print(f"{'Método Evaluado':<22} | {'Precisión':<10} | {'Recall':<10} | {'F1-Score':<10} | {'FP':<5} | {'FN':<5}")
        print("-" * 75)
        
        metodos = [
            ("Reglas Heurísticas WAF", metricas.get("alerta_reglas", {})),
            ("Isolation Forest",      metricas.get("alerta_iforest", {})),
            ("One-Class SVM",         metricas.get("alerta_ocsvm", {})),
            ("Local Outlier Factor",  metricas.get("alerta_lof", {})),
            ("Ensamble ML Completo",  metricas.get("alerta_ml", {})),
        ]
        
        for nombre, m in metodos:
            prec = f"{m.get('precision', 0.0):.3f}"
            rec  = f"{m.get('recall', 0.0):.3f}"
            f1   = f"{m.get('f1', 0.0):.3f}"
            fp   = str(m.get('falsos_positivos', 0))
            fn   = str(m.get('falsos_negativos', 0))
            print(f"{nombre:<22} | {prec:<10} | {rec:<10} | {f1:<10} | {fp:<5} | {fn:<5}")
        print("-" * 75)

    # 5. Descargar dataset CSV
    nombre_archivo = "dataset_ataques_centinela.csv"
    print(f"\n[5/5] Descargando dataset completo en '{nombre_archivo}'...")
    csv_data = peticion(url_base, "/api/exportar_dataset?formato=csv")
    if isinstance(csv_data, str) and "timestamp,ip,usuario" in csv_data:
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            f.write(csv_data)
        lineas = len(csv_data.strip().split("\n"))
        print(f"  ✓ Archivo guardado con éxito: {lineas} filas (incluyendo encabezados).")
    else:
        print("  ⚠️ No se pudo guardar el archivo CSV automáticamente.")

    print("\n✅ Experimento de alta potencia estadística finalizado con éxito.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ejecutor de experimentos para Centinela")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"URL del servidor Centinela (por defecto: {DEFAULT_URL})")
    parser.add_argument("--cantidad", type=int, default=1000, help="Tamaño de la muestra de evaluación (por defecto: 1000)")
    parser.add_argument("--no-reset", action="store_true", help="No reiniciar el estado de la base de datos previa")
    args = parser.parse_args()

    ejecutar_experimento(args.url.rstrip("/"), resetear=not args.no_reset, cantidad=args.cantidad)
