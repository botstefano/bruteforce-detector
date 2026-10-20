import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  FileCheck2,
  Terminal,
  Download,
  Upload,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Copy,
  Check,
  RefreshCw,
  Clock,
  Zap,
  BarChart3,
  Layers,
  Database,
  Lock,
  Flame,
  ArrowRight,
  ExternalLink,
  Code2,
  FileSpreadsheet,
  FileText
} from 'lucide-react';

interface MetricValue {
  media: number;
  std: number;
  min?: number;
  max?: number;
}

interface DetectorMetrics {
  f1: MetricValue;
  recall: MetricValue;
  precision: MetricValue;
  fpr: MetricValue;
  especificidad: MetricValue;
  accuracy: MetricValue;
  auc_roc: MetricValue;
  auc_pr: MetricValue;
  VP: number;
  FP: number;
  FN: number;
  VN: number;
  latencia_ms_por_flujo: MetricValue;
  bootstrap_ci_95?: {
    f1: [number, number];
    recall: [number, number];
    precision: [number, number];
    fpr: [number, number];
  };
}

interface RealCicidsResults {
  origen_datos: string;
  fecha_ejecucion: string;
  semillas_evaluadas: number[];
  n_bootstrap: number;
  hashes_sha256: Record<
    string,
    {
      archivo: string;
      ruta_completa: string;
      tamano_bytes: number;
      sha256: string;
      tiempo_calculo_seg: number;
    }
  >;
  limpieza_datos: Record<
    string,
    {
      etapa: string;
      filas_originales: number;
      filas_nan_o_inf_eliminadas: number;
      filas_tras_nan_inf: number;
      filas_duplicadas_eliminadas: number;
      filas_finales_limpias: number;
      filas_xss_excluidas_documentadas?: number;
      filas_sqli_excluidas_documentadas?: number;
      filas_finales_evaluacion_prueba2?: number;
      conteo_por_etiqueta: Record<string, number>;
    }
  >;
  features_utilizadas: string[];
  calibracion: {
    criterio: string;
    reglas_waf_n: number;
    reglas_waf_n_fpr1: number;
    umbrales_ml_f1: Record<string, number>;
    umbrales_ml_fpr1: Record<string, number>;
  };
  metricas: {
    prueba1_tuesday_natural: Record<string, DetectorMetrics>;
    prueba1_tuesday_balanceado: Record<string, DetectorMetrics>;
    prueba2_thursday_natural: Record<string, DetectorMetrics>;
    prueba2_thursday_balanceado: Record<string, DetectorMetrics>;
    recall_por_tipo_ataque: {
      ftp_patator: Record<string, { media: number; std: number }>;
      ssh_patator: Record<string, { media: number; std: number }>;
      web_brute_force: Record<string, { media: number; std: number }>;
    };
  };
}

interface ValidacionCicidsRealViewProps {
  showToast: (msg: string) => void;
}

const NOMBRES_DETECTOR_DISPLAY: Record<string, { nombre: string; tag: string; color: string; desc: string }> = {
  reglas_waf: {
    nombre: 'Reglas Heurísticas WAF',
    tag: 'WAF',
    color: 'from-amber-500 to-orange-500',
    desc: 'Umbral N flujos/60s a mismo Destination Port (calibrado en Val)'
  },
  isolation_forest: {
    nombre: 'Isolation Forest (Centinela)',
    tag: 'ML-IF',
    color: 'from-blue-500 to-cyan-500',
    desc: 'Árboles de aislamiento no supervisados sobre espacio de flujo'
  },
  one_class_svm: {
    nombre: 'One-Class SVM (Centinela RBF)',
    tag: 'ML-SVM',
    color: 'from-indigo-500 to-purple-500',
    desc: 'Frontera de soporte kernel RBF / distancia estandarizada'
  },
  lof: {
    nombre: 'Local Outlier Factor (LOF Centinela)',
    tag: 'ML-LOF',
    color: 'from-pink-500 to-rose-500',
    desc: 'Estimación de densidad local relativa a k vecinos normales'
  },
  ensamble_centinela: {
    nombre: 'Ensamble Ponderado Centinela',
    tag: 'ENSAMBLE',
    color: 'from-emerald-500 to-teal-500',
    desc: 'Consenso multi-modelo y umbral calibrado en validación'
  },
  random_forest_supervisado: {
    nombre: 'Random Forest Supervisado',
    tag: 'SUPERVISADO (REF)',
    color: 'from-purple-600 to-indigo-600',
    desc: 'Cota superior empírica con etiquetas de entrenamiento'
  }
};

export function ValidacionCicidsRealView({ showToast }: ValidacionCicidsRealViewProps) {
  const [datosReales, setDatosReales] = useState<RealCicidsResults | null>(null);
  const [reporteMd, setReporteMd] = useState<string | null>(null);
  const [cargando, setCargando] = useState(false);
  const [subiendoArchivo, setSubiendoArchivo] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'natural' | 'balanceado' | 'ataques' | 'calibracion' | 'integridad' | 'paper_export'>('natural');
  const [copiado, setCopiado] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Intentar cargar resultados existentes al montar
  useEffect(() => {
    cargarResultadosDelServidor();
  }, []);

  const cargarResultadosDelServidor = async () => {
    setCargando(true);
    try {
      const res = await fetch('/api/cicids/resultados_reales');
      const data = await res.json();
      if (data.existe && data.datos) {
        setDatosReales(data.datos);
        if (data.reporteMd) setReporteMd(data.reporteMd);
        showToast('Resultados reales de CICIDS2017 cargados exitosamente');
      } else {
        setDatosReales(null);
      }
    } catch (e) {
      console.error('Error al consultar resultados reales:', e);
    } finally {
      setCargando(false);
    }
  };

  const handleSubirJson = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSubiendoArchivo(true);
    try {
      const text = await file.text();
      const json = JSON.parse(text);

      if (!json.origen_datos || !json.metricas) {
        showToast('El archivo no parece ser un resultados_cicids_real.json válido');
        setSubiendoArchivo(false);
        return;
      }

      // Enviar al servidor para persistirlo
      const res = await fetch('/api/cicids/cargar_resultados_reales', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(json)
      });
      const dataRes = await res.json();
      if (res.ok) {
        setDatosReales(json);
        showToast('Resultados reales guardados y sincronizados correctamente');
      } else {
        showToast(dataRes.error || 'Error al persistir en servidor');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(`Error al leer archivo JSON: ${msg}`);
    } finally {
      setSubiendoArchivo(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const copiarTexto = (texto: string, clave: string) => {
    navigator.clipboard.writeText(texto);
    setCopiado(clave);
    showToast('Copiado al portapapeles');
    setTimeout(() => setCopiado(null), 2000);
  };

  const descargarReporteMd = () => {
    if (!datosReales) return;
    const contenido = reporteMd || JSON.stringify(datosReales, null, 2);
    const blob = new Blob([contenido], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'reporte_cicids_real.md';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Descargando reporte_cicids_real.md');
  };

  const descargarJson = () => {
    if (!datosReales) return;
    const blob = new Blob([JSON.stringify(datosReales, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'resultados_cicids_real.json';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Descargando resultados_cicids_real.json');
  };

  // Generador de tabla LaTeX IEEEtran
  const generarLatexTable = (): string => {
    if (!datosReales) return '';
    const m1 = datosReales.metricas.prueba1_tuesday_natural;
    const m2 = datosReales.metricas.prueba2_thursday_natural;

    let latex = `% Tabla generada automáticamente para IEEE Transactions / ACM\n`;
    latex += `\\begin{table*}[t]\n`;
    latex += `\\centering\n`;
    latex += `\\caption{Evaluación Empírica sobre Flujos Reales de CICIDS2017 (UNB/CIC) sin Fuga Temporal}\n`;
    latex += `\\label{tab:cicids_real_results}\n`;
    latex += `\\begin{tabular}{lcccccc}\n`;
    latex += `\\hline\n`;
    latex += `\\textbf{Detector} & \\textbf{Prueba} & \\textbf{$F_1$-Score} & \\textbf{Recall (TPR)} & \\textbf{Precisión} & \\textbf{FPR} & \\textbf{AUC-ROC} \\\\\n`;
    latex += `\\hline\n`;

    for (const [detKey, info] of Object.entries(NOMBRES_DETECTOR_DISPLAY)) {
      const v1 = m1[detKey];
      const v2 = m2[detKey];
      if (v1) {
        latex += `${info.nombre} & Tuesday (Patator) & $${v1.f1.media.toFixed(4)} \\pm ${v1.f1.std.toFixed(4)}$ & $${v1.recall.media.toFixed(4)}$ & $${v1.precision.media.toFixed(4)}$ & $${v1.fpr.media.toFixed(4)}$ & $${v1.auc_roc.media.toFixed(4)}$ \\\\\n`;
      }
      if (v2) {
        latex += ` & Thursday (Web Brute Force) & $${v2.f1.media.toFixed(4)} \\pm ${v2.f1.std.toFixed(4)}$ & $${v2.recall.media.toFixed(4)}$ & $${v2.precision.media.toFixed(4)}$ & $${v2.fpr.media.toFixed(4)}$ & $${v2.auc_roc.media.toFixed(4)}$ \\\\\n`;
      }
      latex += `\\hline\n`;
    }

    latex += `\\end{tabular}\n`;
    latex += `\\end{table*}`;
    return latex;
  };

  // Entrada BibTeX canónica
  const bibtex = `@article{sharafaldin2018toward,
  title={Toward generating a new intrusion detection dataset and intrusion traffic characterization},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Ghorbani, Ali A},
  journal={ICISSP},
  pages={108--116},
  year={2018},
  publisher={SCITEPRESS}
}`;

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Encabezado Superior con Origen Verificado */}
      <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-emerald-500/10 via-cyan-500/5 to-transparent rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-black tracking-wider uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                <span>CICIDS2017 real (UNB/CIC)</span>
              </span>
              <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                <span>Partición Temporal Zero-Leakage</span>
              </span>
              <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                <span>10 Semillas & Bootstrap 95%</span>
              </span>
            </div>

            <h1 className="text-2xl lg:text-3xl font-black tracking-tight text-white">
              Validación Científica de Centinela con Datos Reales
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              Evaluación empírica y reproducible de las <strong>Reglas Heurísticas WAF</strong>, <strong>Isolation Forest</strong>, <strong>One-Class SVM</strong>, <strong>LOF</strong> y el <strong>Ensamble Centinela</strong> sobre los flujos de red oficiales de CICIDS2017 (Canadian Institute for Cybersecurity).
            </p>
          </div>

          {/* Botones de acción superior */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <a
              href="/api/cicids/descargar_script_validacion"
              download="validacion_cicids_real.py"
              className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all cursor-pointer shadow-md"
              title="Descargar script Python para ejecución local"
            >
              <Code2 className="w-4 h-4 text-cyan-400" />
              <span>Descargar Script Python</span>
            </a>

            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={subiendoArchivo}
              className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white transition-all cursor-pointer shadow-lg shadow-emerald-600/20 disabled:opacity-50"
            >
              {subiendoArchivo ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Upload className="w-4 h-4" />
              )}
              <span>Cargar resultados_cicids_real.json</span>
            </button>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleSubirJson}
              accept=".json"
              className="hidden"
            />

            <button
              onClick={cargarResultadosDelServidor}
              disabled={cargando}
              className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all cursor-pointer"
              title="Recargar datos del servidor"
            >
              <RefreshCw className={`w-4 h-4 ${cargando ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Si aún NO hay datos cargados, mostrar Guía de Ejecución Local Clara y Detallada */}
      {!datosReales && (
        <div className="space-y-6">
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-3xl p-6 lg:p-8">
            <div className="flex items-start space-x-4">
              <div className="p-3 bg-amber-500/20 rounded-2xl shrink-0 text-amber-400">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div className="space-y-2">
                <h2 className="text-lg font-bold text-amber-300">
                  Esperando Ejecución con Archivos Reales de CICIDS2017
                </h2>
                <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
                  De acuerdo con las reglas estrictas de investigación científica, <strong>ningún número ha sido inventado, simulado ni estimado</strong>.
                  Los archivos oficiales CSV de CICIDS2017 pesan varios gigabytes (más de 3.5 GB) y deben ser procesados en local mediante el script independiente <code className="bg-slate-950 px-2 py-0.5 rounded text-amber-300 font-mono">validacion_cicids_real.py</code> para evitar desbordamientos de memoria en el servidor web.
                </p>
                <div className="pt-2 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3.5 py-2.5 rounded-xl flex items-center justify-between">
                  <span>
                    💡 <strong>¿Quieres cargar y probar tu dataset directamente en el navegador?</strong> Puedes subir o pegar tus filas CSV/TSV de inmediato en la pestaña <strong className="text-white underline">"Dataset CICIDS-2017"</strong>.
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Guía Paso a Paso */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Paso 1 */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-black text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-lg border border-cyan-500/20">
                  PASO 1
                </span>
                <Database className="w-5 h-5 text-slate-500" />
              </div>
              <h3 className="font-bold text-white text-base">Descargar Archivos Oficiales</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Descarga del Canadian Institute for Cybersecurity (UNB/CIC) la versión <strong className="text-slate-200">TrafficLabelling</strong> (con Source IP, Destination IP, Timestamp y Label):
              </p>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                <li><code className="text-cyan-300 font-mono text-[11px]">Monday-WorkingHours.pcap_ISCX.csv</code></li>
                <li><code className="text-cyan-300 font-mono text-[11px]">Tuesday-WorkingHours.pcap_ISCX.csv</code></li>
                <li><code className="text-cyan-300 font-mono text-[11px]">Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv</code></li>
              </ul>
              <a
                href="https://www.unb.ca/cic/datasets/ids-2017.html"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center space-x-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-bold underline pt-2"
              >
                <span>Visitar sitio oficial UNB/CIC</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>

            {/* Paso 2 */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-black text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/20">
                  PASO 2
                </span>
                <Terminal className="w-5 h-5 text-slate-500" />
              </div>
              <h3 className="font-bold text-white text-base">Instalar Dependencias</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Asegúrate de tener Python 3.9+ y las librerías científicas instaladas en tu entorno local:
              </p>
              <div className="relative bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300">
                <code>pip install numpy pandas scikit-learn scipy</code>
                <button
                  onClick={() => copiarTexto('pip install numpy pandas scikit-learn scipy', 'pip')}
                  className="absolute top-2.5 right-2.5 text-slate-400 hover:text-white"
                  title="Copiar comando"
                >
                  {copiado === 'pip' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                O ejecuta <code className="text-slate-400">pip install -r requirements_cicids.txt</code>
              </p>
            </div>

            {/* Paso 3 */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-black text-purple-400 bg-purple-500/10 px-2.5 py-1 rounded-lg border border-purple-500/20">
                  PASO 3
                </span>
                <Zap className="w-5 h-5 text-slate-500" />
              </div>
              <h3 className="font-bold text-white text-base">Ejecutar el Script</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Ejecuta el script apuntando a la carpeta donde descomprimiste los 3 archivos CSV:
              </p>
              <div className="relative bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                <code>python3 validacion_cicids_real.py --data-dir /ruta/a/csvs/</code>
                <button
                  onClick={() => copiarTexto('python3 validacion_cicids_real.py --data-dir /ruta/a/csvs/', 'cmd')}
                  className="absolute top-2.5 right-2.5 text-slate-400 hover:text-white"
                  title="Copiar comando"
                >
                  {copiado === 'cmd' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Genera automáticamente <code className="text-emerald-400">resultados_cicids_real.json</code>, CSV, reporte MD y hashes SHA-256.
              </p>
            </div>
          </div>

          {/* Acciones de carga directa */}
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 text-center space-y-4">
            <div className="inline-flex p-4 bg-emerald-500/10 rounded-2xl text-emerald-400 mb-2">
              <Upload className="w-8 h-8" />
            </div>
            <h3 className="text-xl font-bold text-white">¿Ya ejecutaste el script localmente?</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Sube el archivo <code className="text-cyan-300 font-mono">resultados_cicids_real.json</code> generado para visualizar aquí todas las tablas, métricas e intervalos de confianza listos para tu artículo.
            </p>
            <div className="pt-2">
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-6 py-3 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-sm shadow-xl shadow-emerald-600/20 transition-all cursor-pointer inline-flex items-center space-x-2"
              >
                <Upload className="w-4 h-4" />
                <span>Seleccionar y Subir resultados_cicids_real.json</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Si SÍ hay datos cargados, renderizar la Suite Científica Completa */}
      {datosReales && (
        <div className="space-y-6">
          {/* Barra de Sub-Pestañas */}
          <div className="flex flex-wrap items-center bg-slate-900 p-1.5 rounded-2xl border border-slate-800 gap-1">
            <button
              onClick={() => setActiveSubTab('natural')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeSubTab === 'natural'
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <BarChart3 className="w-4 h-4" />
              <span>Tabla 1: Prevalencia Natural</span>
            </button>

            <button
              onClick={() => setActiveSubTab('balanceado')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeSubTab === 'balanceado'
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Tabla 2: Balanceado (50/50)</span>
            </button>

            <button
              onClick={() => setActiveSubTab('ataques')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeSubTab === 'ataques'
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Flame className="w-4 h-4" />
              <span>Tabla 3: Desglose por Familia</span>
            </button>

            <button
              onClick={() => setActiveSubTab('calibracion')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeSubTab === 'calibracion'
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Clock className="w-4 h-4" />
              <span>Calibración Sin Fuga</span>
            </button>

            <button
              onClick={() => setActiveSubTab('integridad')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeSubTab === 'integridad'
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <FileCheck2 className="w-4 h-4" />
              <span>Integridad SHA-256 & Limpieza</span>
            </button>

            <button
              onClick={() => setActiveSubTab('paper_export')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeSubTab === 'paper_export'
                  ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/30'
                  : 'text-emerald-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Exportar para Artículo (LaTeX/MD)</span>
            </button>
          </div>

          {/* SUB-PESTAÑA 1: PREVALENCIA NATURAL */}
          {activeSubTab === 'natural' && (
            <div className="space-y-6">
              {/* Sección A: Prueba 1 Tuesday (Patator) */}
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                      <span>Prueba 1: Tráfico Tuesday (FTP-Patator y SSH-Patator)</span>
                      <span className="text-xs bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 px-2.5 py-0.5 rounded-full font-semibold">
                        70% Restante Temporal
                      </span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Prevalencia natural no alterada. Métricas promediadas sobre {datosReales.semillas_evaluadas.length} semillas con intervalos bootstrap 95%.
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-[11px] uppercase font-bold text-slate-400 tracking-wider">
                        <th className="py-3 px-3">Detector</th>
                        <th className="py-3 px-3">F1-Score (Media ± Std)</th>
                        <th className="py-3 px-3">Recall (Sensibilidad)</th>
                        <th className="py-3 px-3">Precisión</th>
                        <th className="py-3 px-3">FPR (Falsos Positivos)</th>
                        <th className="py-3 px-3">AUC-ROC</th>
                        <th className="py-3 px-3">Latencia Flujo</th>
                        <th className="py-3 px-3">IC 95% Bootstrap F1</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-xs">
                      {Object.entries(NOMBRES_DETECTOR_DISPLAY).map(([clave, info]) => {
                        const m = datosReales.metricas.prueba1_tuesday_natural[clave];
                        if (!m) return null;
                        const ci = m.bootstrap_ci_95?.f1 || [0, 0];
                        return (
                          <tr key={clave} className="hover:bg-slate-800/30 transition-colors">
                            <td className="py-3 px-3 font-semibold text-white">
                              <div className="flex items-center space-x-2">
                                <span className="text-[10px] px-2 py-0.5 rounded-md font-mono font-bold bg-slate-800 text-cyan-300">
                                  {info.tag}
                                </span>
                                <span>{info.nombre}</span>
                              </div>
                            </td>
                            <td className="py-3 px-3 font-bold text-cyan-400 font-mono">
                              {m.f1.media.toFixed(4)} <span className="text-slate-500 text-[10px]">± {m.f1.std.toFixed(4)}</span>
                            </td>
                            <td className="py-3 px-3 font-mono text-emerald-400">
                              {(m.recall.media * 100).toFixed(2)}%
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-300">
                              {(m.precision.media * 100).toFixed(2)}%
                            </td>
                            <td className="py-3 px-3 font-mono text-amber-400">
                              {(m.fpr.media * 100).toFixed(2)}%
                            </td>
                            <td className="py-3 px-3 font-mono text-purple-300">
                              {m.auc_roc.media.toFixed(4)}
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-400">
                              {m.latencia_ms_por_flujo.media.toFixed(3)} ms
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-400 text-[11px]">
                              [{ci[0].toFixed(4)}, {ci[1].toFixed(4)}]
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Sección B: Prueba 2 Thursday (Web Attacks) */}
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                      <span>Prueba 2: Tráfico Thursday Morning (Web Attack Brute Force)</span>
                      <span className="text-xs bg-purple-500/10 text-purple-400 border border-purple-500/30 px-2.5 py-0.5 rounded-full font-semibold">
                        Evaluación Ciega Independiente
                      </span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      XSS y SQL Injection excluidas de acuerdo a la especificación estricta. Umbrales fijados en martes sin calibración previa en jueves.
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-[11px] uppercase font-bold text-slate-400 tracking-wider">
                        <th className="py-3 px-3">Detector</th>
                        <th className="py-3 px-3">F1-Score (Media ± Std)</th>
                        <th className="py-3 px-3">Recall (Sensibilidad)</th>
                        <th className="py-3 px-3">Precisión</th>
                        <th className="py-3 px-3">FPR</th>
                        <th className="py-3 px-3">AUC-ROC</th>
                        <th className="py-3 px-3">Latencia Flujo</th>
                        <th className="py-3 px-3">IC 95% Bootstrap F1</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-xs">
                      {Object.entries(NOMBRES_DETECTOR_DISPLAY).map(([clave, info]) => {
                        const m = datosReales.metricas.prueba2_thursday_natural[clave];
                        if (!m) return null;
                        const ci = m.bootstrap_ci_95?.f1 || [0, 0];
                        return (
                          <tr key={clave} className="hover:bg-slate-800/30 transition-colors">
                            <td className="py-3 px-3 font-semibold text-white">
                              <div className="flex items-center space-x-2">
                                <span className="text-[10px] px-2 py-0.5 rounded-md font-mono font-bold bg-slate-800 text-purple-300">
                                  {info.tag}
                                </span>
                                <span>{info.nombre}</span>
                              </div>
                            </td>
                            <td className="py-3 px-3 font-bold text-purple-400 font-mono">
                              {m.f1.media.toFixed(4)} <span className="text-slate-500 text-[10px]">± {m.f1.std.toFixed(4)}</span>
                            </td>
                            <td className="py-3 px-3 font-mono text-emerald-400">
                              {(m.recall.media * 100).toFixed(2)}%
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-300">
                              {(m.precision.media * 100).toFixed(2)}%
                            </td>
                            <td className="py-3 px-3 font-mono text-amber-400">
                              {(m.fpr.media * 100).toFixed(2)}%
                            </td>
                            <td className="py-3 px-3 font-mono text-cyan-300">
                              {m.auc_roc.media.toFixed(4)}
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-400">
                              {m.latencia_ms_por_flujo.media.toFixed(3)} ms
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-400 text-[11px]">
                              [{ci[0].toFixed(4)}, {ci[1].toFixed(4)}]
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* SUB-PESTAÑA 2: BALANCEADO 50/50 */}
          {activeSubTab === 'balanceado' && (
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-4">
              <div className="border-b border-slate-800 pb-4">
                <h3 className="text-lg font-bold text-white">
                  Tabla 2: Evaluación con Submuestreo Balanceado (50% Benigno / 50% Ataque)
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Permite evaluar el desempeño del modelo sin el sesgo inducido por la alta prevalencia de tráfico benigno.
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-[11px] uppercase font-bold text-slate-400 tracking-wider">
                      <th className="py-3 px-3">Detector</th>
                      <th className="py-3 px-3">F1 Prueba 1 (Patator)</th>
                      <th className="py-3 px-3">F1 Prueba 2 (Web Brute Force)</th>
                      <th className="py-3 px-3">Recall P1</th>
                      <th className="py-3 px-3">Recall P2</th>
                      <th className="py-3 px-3">Especificidad P1</th>
                      <th className="py-3 px-3">Especificidad P2</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                    {Object.entries(NOMBRES_DETECTOR_DISPLAY).map(([clave, info]) => {
                      const v1 = datosReales.metricas.prueba1_tuesday_balanceado[clave];
                      const v2 = datosReales.metricas.prueba2_thursday_balanceado[clave];
                      if (!v1 || !v2) return null;
                      return (
                        <tr key={clave} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 px-3 font-sans font-semibold text-white">
                            {info.nombre}
                          </td>
                          <td className="py-3 px-3 text-cyan-400 font-bold">{v1.f1.media.toFixed(4)}</td>
                          <td className="py-3 px-3 text-purple-400 font-bold">{v2.f1.media.toFixed(4)}</td>
                          <td className="py-3 px-3 text-emerald-400">{(v1.recall.media * 100).toFixed(2)}%</td>
                          <td className="py-3 px-3 text-emerald-400">{(v2.recall.media * 100).toFixed(2)}%</td>
                          <td className="py-3 px-3 text-slate-300">{(v1.especificidad.media * 100).toFixed(2)}%</td>
                          <td className="py-3 px-3 text-slate-300">{(v2.especificidad.media * 100).toFixed(2)}%</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SUB-PESTAÑA 3: DESGLOSE POR TIPO DE ATAQUE */}
          {activeSubTab === 'ataques' && (
            <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-4">
              <div className="border-b border-slate-800 pb-4">
                <h3 className="text-lg font-bold text-white">
                  Tabla 3: Tasa de Detección (Recall) Desglosada por Familia Específica de Ataque
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Compara la capacidad de detección frente a protocolos de autenticación clásicos (FTP y SSH) versus ataques de fuerza bruta web en HTTP.
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-[11px] uppercase font-bold text-slate-400 tracking-wider">
                      <th className="py-3 px-3">Detector</th>
                      <th className="py-3 px-3">FTP-Patator (Puerto 21)</th>
                      <th className="py-3 px-3">SSH-Patator (Puerto 22)</th>
                      <th className="py-3 px-3">Web Attack Brute Force (Puerto 80)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs">
                    {Object.entries(NOMBRES_DETECTOR_DISPLAY).map(([clave, info]) => {
                      const ftp = datosReales.metricas.recall_por_tipo_ataque.ftp_patator[clave];
                      const ssh = datosReales.metricas.recall_por_tipo_ataque.ssh_patator[clave];
                      const web = datosReales.metricas.recall_por_tipo_ataque.web_brute_force[clave];
                      if (!ftp || !ssh || !web) return null;
                      return (
                        <tr key={clave} className="hover:bg-slate-800/30 transition-colors font-mono">
                          <td className="py-3 px-3 font-sans font-semibold text-white">
                            {info.nombre}
                          </td>
                          <td className="py-3 px-3 text-cyan-400 font-bold">
                            {(ftp.media * 100).toFixed(2)}% <span className="text-slate-500 text-[10px]">± {(ftp.std * 100).toFixed(2)}%</span>
                          </td>
                          <td className="py-3 px-3 text-emerald-400 font-bold">
                            {(ssh.media * 100).toFixed(2)}% <span className="text-slate-500 text-[10px]">± {(ssh.std * 100).toFixed(2)}%</span>
                          </td>
                          <td className="py-3 px-3 text-purple-400 font-bold">
                            {(web.media * 100).toFixed(2)}% <span className="text-slate-500 text-[10px]">± {(web.std * 100).toFixed(2)}%</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SUB-PESTAÑA 4: CALIBRACIÓN SIN FUGA */}
          {activeSubTab === 'calibracion' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 space-y-4">
                <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
                  <Clock className="w-5 h-5 text-amber-400" />
                  <h3 className="font-bold text-white text-base">Calibración de Reglas WAF (Flujos N)</h3>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  El parámetro <code className="text-amber-300 font-mono">N</code> (número de flujos en ventana de 60s hacia el mismo puerto destino) se determinó estrictamente sobre el primer 30% cronológico de Tuesday:
                </p>
                <div className="bg-slate-950 p-4 rounded-2xl border border-slate-800 space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-400">Umbral N Óptimo (Max F1):</span>
                    <span className="font-bold font-mono text-cyan-300 text-sm">
                      N = {datosReales.calibracion.reglas_waf_n} flujos/60s
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-400">Umbral N con FPR Objetivo ≤ 1.0%:</span>
                    <span className="font-bold font-mono text-emerald-300 text-sm">
                      N = {datosReales.calibracion.reglas_waf_n_fpr1} flujos/60s
                    </span>
                  </div>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 space-y-4">
                <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
                  <Lock className="w-5 h-5 text-cyan-400" />
                  <h3 className="font-bold text-white text-base">Umbrales de Decisión ML Calibrados</h3>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Los umbrales de corte de probabilidad/anomalía fueron congelados antes de evaluar las particiones ciegos de prueba:
                </p>
                <div className="bg-slate-950 p-4 rounded-2xl border border-slate-800 space-y-2 font-mono text-xs">
                  {Object.entries(datosReales.calibracion.umbrales_ml_f1).map(([modelo, umbral]) => (
                    <div key={modelo} className="flex justify-between items-center">
                      <span className="text-slate-400">{modelo}:</span>
                      <span className="text-cyan-400 font-bold">{umbral.toFixed(4)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* SUB-PESTAÑA 5: INTEGRIDAD SHA-256 & LIMPIEZA */}
          {activeSubTab === 'integridad' && (
            <div className="space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-4">
                <div className="border-b border-slate-800 pb-4">
                  <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                    <FileCheck2 className="w-5 h-5 text-emerald-400" />
                    <span>Hashes Criptográficos SHA-256 de los CSV Oficiales</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Garantiza la trazabilidad y reproducibilidad del experimento con los archivos originales de UNB/CIC.
                  </p>
                </div>

                <div className="space-y-3">
                  {Object.entries(datosReales.hashes_sha256).map(([clave, h]) => (
                    <div key={clave} className="bg-slate-950 p-4 rounded-2xl border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-bold text-white">{h.archivo}</span>
                          <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">
                            {(h.tamano_bytes / (1024 * 1024)).toFixed(1)} MB
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-emerald-400 select-all break-all">
                          SHA-256: {h.sha256}
                        </div>
                      </div>
                      <button
                        onClick={() => copiarTexto(h.sha256, clave)}
                        className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs shrink-0 self-start sm:self-center cursor-pointer"
                        title="Copiar Hash SHA-256"
                      >
                        {copiado === clave ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Registro de Limpieza */}
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-4">
                <h3 className="text-lg font-bold text-white">Registro de Limpieza y Conteos de Filas</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {Object.entries(datosReales.limpieza_datos).map(([clave, lim]) => (
                    <div key={clave} className="bg-slate-950 p-4 rounded-2xl border border-slate-800 space-y-2 text-xs">
                      <h4 className="font-bold text-cyan-300 text-sm capitalize">{lim.etapa}</h4>
                      <div className="flex justify-between text-slate-400">
                        <span>Filas originales:</span>
                        <span className="font-mono text-slate-200">{lim.filas_originales.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>NaN / Inf eliminados:</span>
                        <span className="font-mono text-amber-400">-{lim.filas_nan_o_inf_eliminadas.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Duplicados exactos:</span>
                        <span className="font-mono text-amber-400">-{lim.filas_duplicadas_eliminadas.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-slate-400 border-t border-slate-800 pt-1.5 font-bold">
                        <span className="text-emerald-400">Filas limpias finales:</span>
                        <span className="font-mono text-emerald-300">{lim.filas_finales_limpias.toLocaleString()}</span>
                      </div>
                      {lim.filas_xss_excluidas_documentadas !== undefined && (
                        <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-900">
                          Excluidas documentadas: {lim.filas_xss_excluidas_documentadas} XSS, {lim.filas_sqli_excluidas_documentadas} SQLi
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* SUB-PESTAÑA 6: EXPORTAR PARA ARTÍCULO CIENTÍFICO */}
          {activeSubTab === 'paper_export' && (
            <div className="space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                      <FileText className="w-5 h-5 text-emerald-400" />
                      <span>Tablas y Manuscrito Listos para Publicación</span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Copia el código LaTeX para tu manuscrito en IEEE / ACM o descarga el reporte Markdown completo.
                    </p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={descargarReporteMd}
                      className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
                    >
                      <Download className="w-4 h-4" />
                      <span>reporte_cicids_real.md</span>
                    </button>
                    <button
                      onClick={descargarJson}
                      className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
                    >
                      <Download className="w-4 h-4" />
                      <span>resultados_cicids_real.json</span>
                    </button>
                  </div>
                </div>

                {/* Código LaTeX de la Tabla */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                      Código LaTeX (IEEEtran / ACM Table*)
                    </span>
                    <button
                      onClick={() => copiarTexto(generarLatexTable(), 'latex')}
                      className="inline-flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 font-bold"
                    >
                      {copiado === 'latex' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      <span>Copiar LaTeX</span>
                    </button>
                  </div>
                  <pre className="bg-slate-950 p-4 rounded-2xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-72">
                    <code>{generarLatexTable()}</code>
                  </pre>
                </div>

                {/* Entrada BibTeX */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                      Cita Canónica BibTeX (Sharafaldin et al. 2018)
                    </span>
                    <button
                      onClick={() => copiarTexto(bibtex, 'bibtex')}
                      className="inline-flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 font-bold"
                    >
                      {copiado === 'bibtex' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      <span>Copiar BibTeX</span>
                    </button>
                  </div>
                  <pre className="bg-slate-950 p-4 rounded-2xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                    <code>{bibtex}</code>
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
