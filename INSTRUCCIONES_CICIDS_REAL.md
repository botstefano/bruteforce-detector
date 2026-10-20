# Protocolo de Validación Empírica con Datos Reales de CICIDS2017 (UNB/CIC)

Guía completa para la ejecución del experimento independiente con los datasets oficiales de tráfico de red de **CICIDS2017** para inclusión de resultados en artículos científicos.

---

## 1. Fundamento y Reglas Estrictas de la Investigación

1. **Procedencia Oficial**: Los datos deben provenir exclusivamente de la versión oficial **TrafficLabelling** (o GeneratedLabelledFlows) del Canadian Institute for Cybersecurity (UNB/CIC).
2. **Cero Simulación / Cero Ficticio**: Ningún número se inventa ni se aproxima con generadores sintéticos. Toda métrica se computa directamente sobre los archivos CSV reales.
3. **Ausencia Estricta de Fuga Temporal (Zero-Leakage Temporal Split)**:
   - **Entrenamiento**: 100% Tráfico Benigno de `Monday-WorkingHours.pcap_ISCX.csv`.
   - **Calibración de Umbrales**: Primeros 30% en orden cronológico por `Timestamp` de `Tuesday-WorkingHours.pcap_ISCX.csv`. El umbral óptimo $F_1$ y el umbral con $\text{FPR} \le 1.0\%$ se calibran y se **congelan** antes de evaluar en prueba.
   - **Prueba 1 (Test 1)**: El 70% restante temporal de `Tuesday-WorkingHours.pcap_ISCX.csv` (evaluando detección de **FTP-Patator** y **SSH-Patator**).
   - **Prueba 2 (Test 2)**: 100% de `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (evaluando detección de **Web Attack – Brute Force**; los ataques XSS y SQL Injection son excluidos y documentados explícitamente).
4. **Ingeniería de Características en Ventanas de 60 Segundos**:
   - Para cada flujo se calculan métricas temporales por `Source IP` en ventana deslizante de 60 segundos:
     * `src_flows_same_dst_port_60s`: Número de flujos hacia el mismo puerto destino.
     * `src_interflow_mean_60s`: Promedio de tiempo de inter-llegada entre flujos de esa IP.
     * `src_interflow_std_60s`: Desviación estándar de los tiempos entre flujos.
5. **Calibración de Reglas WAF**:
   - Se barre el parámetro $N$ (flujos a mismo puerto en 60s) en el tramo de validación de Tuesday (30%) seleccionando el que maximiza $F_1$. Ese $N^*$ se fija para Test 1 y Test 2.

---

## 2. Requisitos e Instalación en tu Entorno Local

Dado que los archivos oficiales de CICIDS2017 pesan más de **3.5 GB**, el procesamiento debe realizarse en tu máquina local o servidor con suficiente memoria RAM (8 GB+ recomendado).

### Paso 2.1: Instalar dependencias de Python

```bash
pip install -r requirements_cicids.txt
```

O manualmente:

```bash
pip install numpy pandas scikit-learn scipy
```

---

## 3. Descarga de los Archivos Oficiales de UNB/CIC

1. Ingresa al portal oficial: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Descarga los archivos CSV de la sección **TrafficLabelling** (o GeneratedLabelledFlows):
   - `Monday-WorkingHours.pcap_ISCX.csv`
   - `Tuesday-WorkingHours.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
3. Colócalos en una carpeta local, por ejemplo: `/home/usuario/cicids2017/` o `C:\datasets\cicids2017\`.

---

## 4. Ejecución del Script de Validación

Ejecuta el script apuntando al directorio donde guardaste los archivos CSV:

```bash
python3 validacion_cicids_real.py --data-dir /ruta/a/la/carpeta/ [opciones]
```

### Opciones Disponibles:

- `--data-dir`: Ruta a la carpeta con los CSVs oficiales (**Obligatoria si no están en la carpeta actual**).
- `--output-dir`: Carpeta donde se escribirán los resultados (por defecto: `./`).
- `--num-seeds`: Cantidad de semillas aleatorias para repeticiones estadísticas (por defecto: `10`).
- `--n-bootstrap`: Número de iteraciones bootstrap para intervalos de confianza al 95% (por defecto: `1000`).
- `--max-train-samples`: Tamaño máximo de submuestreo de tráfico benigno para algoritmos no lineales cuadráticos como SVM (por defecto: `40000`).

---

## 5. Salidas Generadas para el Artículo Científico

El script genera 4 archivos cruciales:

1. `resultados_cicids_real.json`: Objeto JSON completo con todas las métricas, matrices de confusión, curvas, prevalencia natural y balanceada, e intervalos bootstrap al 95%.
2. `resultados_cicids_real.csv`: Tabla plana con todas las combinaciones de detector, prueba y métricas estadísticas (Media, Desv. Estándar, Latencias).
3. `reporte_cicids_real.md`: Reporte en Markdown con las Tablas 1, 2 y 3 formateadas con rigor académico listas para incluir en el paper.
4. `reproducibilidad_cicids.json`: Certificado con hashes criptográficos **SHA-256** de cada CSV, conteos exactos de filas antes/después de limpieza, versiones de Python y scikit-learn utilizadas.

---

## 6. Visualización en el Panel de Centinela

Para visualizar los resultados en la interfaz gráfica web de Centinela:

1. Ve a la pestaña **"Validación CICIDS2017 (datos reales)"** en la barra de navegación superior.
2. Haz clic en **"Cargar resultados_cicids_real.json"** y selecciona el archivo JSON generado por el script.
3. El panel validará la procedencia, mostrará los hashes SHA-256, las tablas comparativas interactivas, y te permitirá copiar el código **LaTeX (IEEEtran/ACM)** y **BibTeX** con un solo clic.
