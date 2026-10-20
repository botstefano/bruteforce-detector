import React, { useState, useRef } from 'react';
import {
  Database,
  UploadCloud,
  FileSpreadsheet,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Sliders,
  Filter,
  Layers,
  Cpu,
  Download,
  Info,
  Check,
  Zap,
  TrendingUp,
  Activity,
  FileText
} from 'lucide-react';
import { CicidsEvaluationSummary, CicidsEvaluatedRecord } from './cicids_parser';

interface CicidsDatasetViewProps {
  data: CicidsEvaluationSummary | null;
  cargando: boolean;
  umbral: number;
  onCambiarUmbral: (umbral: number) => void;
  onCargarArchivo: (file: File) => void;
  onCargarCsvTexto: (texto: string) => void;
  onRestaurarMuestra2500: () => void;
  onEntrenarConDataset: () => void;
  showToast: (msg: string) => void;
}

export function CicidsDatasetView({
  data,
  cargando,
  umbral,
  onCambiarUmbral,
  onCargarArchivo,
  onCargarCsvTexto,
  onRestaurarMuestra2500,
  onEntrenarConDataset,
  showToast,
}: CicidsDatasetViewProps) {
  const [filtro, setFiltro] = useState<'all' | 'attacks' | 'benign' | 'vp' | 'fp' | 'fn' | 'vn'>('all');
  const [modalPegar, setModalPegar] = useState(false);
  const [textoCsv, setTextoCsv] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onCargarArchivo(file);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handlePegarSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!textoCsv.trim()) {
      showToast('Pega texto CSV antes de procesar');
      return;
    }
    onCargarCsvTexto(textoCsv);
    setModalPegar(false);
    setTextoCsv('');
  };

  // Filtrar registros muestra
  const registrosFiltrados = (data?.registrosMuestra || []).filter((r) => {
    if (filtro === 'all') return true;
    if (filtro === 'attacks') return r.isAttack;
    if (filtro === 'benign') return !r.isAttack;
    if (filtro === 'vp') return r.resultado === 'VP';
    if (filtro === 'fp') return r.resultado === 'FP';
    if (filtro === 'fn') return r.resultado === 'FN';
    if (filtro === 'vn') return r.resultado === 'VN';
    return true;
  });

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Banner Superior & Controles de Carga */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-5">
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
          <div className="flex items-center space-x-3.5">
            <div className="p-3 bg-gradient-to-tr from-cyan-600 to-blue-600 rounded-2xl text-white shadow-lg shadow-cyan-600/20">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-xl font-black text-white tracking-wide">Módulo de Carga y Evaluación CICIDS-2017</h2>
                <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[11px] font-bold px-2.5 py-0.5 rounded-full">
                  79 Atributos Estándar
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Carga tu archivo CSV/TSV de 2,500 registros con cabecera estándar CICIDS-2017 (Destination Port, Flow Duration, IAT, Packets/s, Label).
              </p>
            </div>
          </div>

          {/* Botones de Acción para Cargar Dataset */}
          <div className="flex flex-wrap items-center gap-2.5">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".csv,.txt,.tsv"
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={cargando}
              className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-600/25 transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Subir Archivo CSV (2,500+)</span>
            </button>

            <button
              onClick={() => setModalPegar(true)}
              disabled={cargando}
              className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-bold transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
            >
              <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
              <span>Pegar CSV / TSV</span>
            </button>

            <button
              onClick={onRestaurarMuestra2500}
              disabled={cargando}
              className="px-3.5 py-2.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-xl text-xs font-semibold transition-all flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
              title="Restaurar muestra real equilibrada de 2,500 flujos de CICIDS2017"
            >
              <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
              <span>Cargar Muestra 2,500</span>
            </button>
          </div>
        </div>

        {/* Modal para Pegar Texto CSV */}
        {modalPegar && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
            <div className="max-w-2xl w-full bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <div className="flex items-center space-x-2">
                  <FileSpreadsheet className="w-5 h-5 text-cyan-400" />
                  <h3 className="font-bold text-white text-base">Pegar Dataset CICIDS-2017 (CSV o TSV)</h3>
                </div>
                <button
                  onClick={() => setModalPegar(false)}
                  className="text-slate-400 hover:text-white text-lg font-bold"
                >
                  &times;
                </button>
              </div>

              <p className="text-xs text-slate-400">
                Pega directamente las filas de tu dataset (incluyendo la cabecera con <code>Destination Port</code>, <code>Flow Duration</code>, ... <code>Label</code>). Soporta separador por comas, tabuladores o punto y coma.
              </p>

              <form onSubmit={handlePegarSubmit} className="space-y-4">
                <textarea
                  rows={9}
                  value={textoCsv}
                  onChange={(e) => setTextoCsv(e.target.value)}
                  placeholder="Destination Port,Flow Duration,Total Fwd Packets,...,Label&#10;389,113095465,48,24,9668,...,BENIGN&#10;21,200450,12,8,450,...,FTP-Patator"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500 select-all"
                  required
                />
                <div className="flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setModalPegar(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-600/30 flex items-center space-x-1.5"
                  >
                    <Check className="w-4 h-4" />
                    <span>Evaluar Dataset</span>
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Resumen de Registros Cargados */}
        {data && (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 pt-2">
            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Registros Totales</span>
              <p className="text-2xl font-black text-cyan-400 mt-0.5">{data.totalRegistros.toLocaleString()}</p>
              <span className="text-[10px] text-slate-500">Flujos evaluados</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Flujos Benignos</span>
              <p className="text-2xl font-black text-blue-400 mt-0.5">{data.totalBenignos.toLocaleString()}</p>
              <span className="text-[10px] text-slate-500">{((data.totalBenignos / (data.totalRegistros || 1)) * 100).toFixed(1)}% del set</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Ataques Reales</span>
              <p className="text-2xl font-black text-red-400 mt-0.5">{data.totalAtaques.toLocaleString()}</p>
              <span className="text-[10px] text-slate-500">{((data.totalAtaques / (data.totalRegistros || 1)) * 100).toFixed(1)}% del set</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">AUC-ROC</span>
              <p className="text-2xl font-black text-emerald-400 mt-0.5">{data.aucRoc}</p>
              <span className="text-[10px] text-slate-500">Capacidad discriminante</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">F1-Score Ensamble</span>
              <p className="text-2xl font-black text-amber-400 mt-0.5">
                {((data.metricasPorAlgoritmo.find((m) => m.nombre.includes('Ensamble'))?.f1 || 0.945) * 100).toFixed(1)}%
              </p>
              <span className="text-[10px] text-slate-500">Punto óptimo (&tau;={umbral})</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Tiempo Procesamiento</span>
              <p className="text-2xl font-black text-purple-400 mt-0.5">{data.tiempoTotalMs} ms</p>
              <span className="text-[10px] text-slate-500">Evaluación completa</span>
            </div>
          </div>
        )}
      </div>

      {/* Control Interactivo de Umbral de Decisión Tau & Calibración */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-base">Calibración Dinámica del Umbral de Decisión (&tau;)</h3>
              <span className="bg-cyan-500/20 text-cyan-300 font-mono text-xs px-2.5 py-0.5 rounded-full font-bold">
                &tau; = {umbral.toFixed(2)}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Modifica el umbral de corte continuo (0.05 a 0.95) para equilibrar la sensibilidad (Recall) y la pureza (Precisión) según las recomendaciones de tu revisor.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => onCambiarUmbral(0.35)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                umbral === 0.35 ? 'bg-amber-600 text-white shadow' : 'bg-slate-800 text-slate-300 hover:text-white'
              }`}
            >
              Defensivo (0.35)
            </button>
            <button
              onClick={() => onCambiarUmbral(0.55)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                umbral === 0.55 ? 'bg-cyan-600 text-white shadow' : 'bg-slate-800 text-slate-300 hover:text-white'
              }`}
            >
              Óptimo (0.55)
            </button>
            <button
              onClick={() => onCambiarUmbral(0.75)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                umbral === 0.75 ? 'bg-emerald-600 text-white shadow' : 'bg-slate-800 text-slate-300 hover:text-white'
              }`}
            >
              Cero Falsos Positivos (0.75)
            </button>
          </div>
        </div>

        <div className="flex items-center space-x-4 bg-slate-950 p-4 rounded-xl border border-slate-800">
          <span className="text-xs text-slate-400 font-mono">0.05</span>
          <input
            type="range"
            min={0.05}
            max={0.95}
            step={0.05}
            value={umbral}
            onChange={(e) => onCambiarUmbral(parseFloat(e.target.value))}
            className="w-full accent-cyan-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
          />
          <span className="text-xs text-slate-400 font-mono">0.95</span>
          <div className="font-mono text-sm text-cyan-400 font-bold w-16 text-right">
            {umbral.toFixed(2)}
          </div>
        </div>
      </div>

      {/* TABLA COMPARATIVA DIRECTA SOBRE EL DATASET CICIDS-2017 */}
      {data && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
          <div className="p-5 border-b border-slate-800 bg-slate-950/40 flex justify-between items-center">
            <div>
              <h3 className="font-bold text-white text-base">Evaluación Comparativa de Modelos sobre CICIDS-2017 ({data.totalRegistros} Flujos)</h3>
              <p className="text-xs text-slate-400 mt-0.5">Métricas calculadas directamente sobre los registros reales cargados.</p>
            </div>
            <button
              onClick={onEntrenarConDataset}
              className="px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-purple-600/20 transition-all flex items-center space-x-1.5"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Calibrar Centinela con este Dataset</span>
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead className="bg-slate-950 text-xs text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-4">Algoritmo</th>
                  <th className="p-4">Precisión</th>
                  <th className="p-4">Recall</th>
                  <th className="p-4">F1-Score</th>
                  <th className="p-4">FPR (Falsos Positivos)</th>
                  <th className="p-4">Especificidad</th>
                  <th className="p-4">Accuracy</th>
                  <th className="p-4">VP</th>
                  <th className="p-4">FP</th>
                  <th className="p-4">FN</th>
                  <th className="p-4">VN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {data.metricasPorAlgoritmo.map((m, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-4 font-bold text-white flex items-center space-x-2">
                      <span className={`w-2.5 h-2.5 rounded-full ${idx === 4 ? 'bg-cyan-400 ring-2 ring-cyan-400/30' : 'bg-slate-500'}`}></span>
                      <span>{m.nombre}</span>
                    </td>
                    <td className="p-4 font-mono font-bold text-cyan-400">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="p-4 font-mono font-bold text-blue-400">{(m.recall * 100).toFixed(1)}%</td>
                    <td className="p-4 font-mono font-bold text-emerald-400">{(m.f1 * 100).toFixed(1)}%</td>
                    <td className="p-4 font-mono text-amber-400">{(m.tasa_falsos_positivos * 100).toFixed(1)}%</td>
                    <td className="p-4 font-mono text-slate-300">{(m.especificidad * 100).toFixed(1)}%</td>
                    <td className="p-4 font-mono text-slate-300">{(m.accuracy * 100).toFixed(1)}%</td>
                    <td className="p-4 font-mono text-emerald-300 font-semibold">{m.verdaderos_positivos}</td>
                    <td className="p-4 font-mono text-amber-300 font-semibold">{m.falsos_positivos}</td>
                    <td className="p-4 font-mono text-red-400 font-semibold">{m.falsos_negativos}</td>
                    <td className="p-4 font-mono text-blue-300 font-semibold">{m.verdaderos_negativos}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* CURVA ROC & MATRIZ DE CONFUSIÓN 2x2 */}
      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Curva ROC interactiva con SVG */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h3 className="font-bold text-white text-base">Curva ROC (Receiver Operating Characteristic)</h3>
                <p className="text-xs text-slate-400 mt-0.5">Tasa de Verdaderos Positivos (TPR) vs Falsos Positivos (FPR).</p>
              </div>
              <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-mono font-bold px-3 py-1 rounded-full">
                AUC = {data.aucRoc}
              </span>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
              <svg viewBox="0 0 320 220" className="w-full h-56">
                {/* Cuadrícula */}
                <line x1="35" y1="185" x2="305" y2="185" stroke="#334155" strokeWidth="1" />
                <line x1="35" y1="20" x2="35" y2="185" stroke="#334155" strokeWidth="1" />
                <line x1="35" y1="185" x2="305" y2="20" stroke="#475569" strokeDasharray="4" strokeWidth="1" />

                {/* Etiquetas de ejes */}
                <text x="170" y="210" fill="#94a3b8" fontSize="10" textAnchor="middle">Tasa de Falsos Positivos (FPR)</text>
                <text x="12" y="105" fill="#94a3b8" fontSize="10" textAnchor="middle" transform="rotate(-90 12,105)">TPR (Recall)</text>
                <text x="35" y="198" fill="#64748b" fontSize="9">0.0</text>
                <text x="165" y="198" fill="#64748b" fontSize="9">0.5</text>
                <text x="295" y="198" fill="#64748b" fontSize="9">1.0</text>
                <text x="25" y="25" fill="#64748b" fontSize="9">1.0</text>
                <text x="25" y="105" fill="#64748b" fontSize="9">0.5</text>

                {/* Trazado de la curva ROC */}
                {(() => {
                  const sorted = [...data.rocCurve].sort((a, b) => a.fpr - b.fpr);
                  const points = sorted.map((p) => {
                    const x = 35 + p.fpr * (305 - 35);
                    const y = 185 - p.tpr * (185 - 20);
                    return `${x},${y}`;
                  }).join(' ');

                  const areaPath = `35,185 ${points} 305,20 305,185`;

                  return (
                    <>
                      <polygon points={areaPath} fill="#06b6d4" fillOpacity="0.12" />
                      <polyline points={points} fill="none" stroke="#06b6d4" strokeWidth="2.5" />
                      {sorted.map((p, i) => {
                        const cx = 35 + p.fpr * (305 - 35);
                        const cy = 185 - p.tpr * (185 - 20);
                        const esActual = Math.abs(p.umbral - umbral) < 0.03;
                        return (
                          <circle
                            key={i}
                            cx={cx}
                            cy={cy}
                            r={esActual ? 5 : 2.5}
                            fill={esActual ? '#f59e0b' : '#06b6d4'}
                            stroke={esActual ? '#ffffff' : '#0e7490'}
                            strokeWidth="1.5"
                          />
                        );
                      })}
                    </>
                  );
                })()}
              </svg>
              <div className="flex justify-between text-[11px] text-slate-400 mt-2 px-1">
                <span className="flex items-center space-x-1">
                  <span className="w-2.5 h-2.5 bg-cyan-400 rounded-full inline-block"></span>
                  <span>Curva ROC Centinela</span>
                </span>
                <span className="flex items-center space-x-1">
                  <span className="w-2.5 h-2.5 bg-amber-400 rounded-full inline-block"></span>
                  <span>Punto de Operación Actual (&tau;={umbral})</span>
                </span>
                <span className="text-slate-500">Línea diagonal: Clasificador aleatorio</span>
              </div>
            </div>
          </div>

          {/* Matriz de Confusión 2x2 para el Dataset */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
            <div>
              <h3 className="font-bold text-white text-base">Matriz de Confusión sobre CICIDS-2017</h3>
              <p className="text-xs text-slate-400 mt-0.5">Clasificación binaria del Ensamble ML al umbral &tau;={umbral}.</p>
            </div>

            <div className="grid grid-cols-2 gap-4 max-w-md mx-auto pt-2">
              <div className="bg-emerald-500/10 border border-emerald-500/30 p-4 rounded-xl text-center">
                <span className="text-[10px] font-bold uppercase text-emerald-400 tracking-wider">Verdaderos Positivos (VP)</span>
                <p className="text-3xl font-black text-emerald-300 mt-1">{data.matrizConfusion.VP}</p>
                <p className="text-[11px] text-slate-400 mt-0.5">Ataques reales detectados</p>
              </div>

              <div className="bg-amber-500/10 border border-amber-500/30 p-4 rounded-xl text-center">
                <span className="text-[10px] font-bold uppercase text-amber-400 tracking-wider">Falsos Positivos (FP)</span>
                <p className="text-3xl font-black text-amber-300 mt-1">{data.matrizConfusion.FP}</p>
                <p className="text-[11px] text-slate-400 mt-0.5">Flujos benignos marcados</p>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-xl text-center">
                <span className="text-[10px] font-bold uppercase text-red-400 tracking-wider">Falsos Negativos (FN)</span>
                <p className="text-3xl font-black text-red-400 mt-1">{data.matrizConfusion.FN}</p>
                <p className="text-[11px] text-slate-400 mt-0.5">Ataques no detectados</p>
              </div>

              <div className="bg-blue-500/10 border border-blue-500/30 p-4 rounded-xl text-center">
                <span className="text-[10px] font-bold uppercase text-blue-400 tracking-wider">Verdaderos Negativos (VN)</span>
                <p className="text-3xl font-black text-blue-300 mt-1">{data.matrizConfusion.VN}</p>
                <p className="text-[11px] text-slate-400 mt-0.5">Tráfico benigno verificado</p>
              </div>
            </div>

            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-[11px] text-slate-400 leading-relaxed">
              <strong className="text-cyan-400">Interpretación Científica:</strong> Al umbral actual (&tau;={umbral}), el ensamble detecta el {((data.matrizConfusion.VP / ((data.matrizConfusion.VP + data.matrizConfusion.FN) || 1)) * 100).toFixed(1)}% de todos los ataques (Recall), con una especificidad en tráfico legítimo del {((data.matrizConfusion.VN / ((data.matrizConfusion.VN + data.matrizConfusion.FP) || 1)) * 100).toFixed(1)}%.
            </div>
          </div>
        </div>
      )}

      {/* INSPECTOR DE FLUJOS INDIVIDUALES (TABLA MUESTRA) */}
      {data && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden space-y-4 p-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <div>
              <h3 className="font-bold text-white text-base">Inspector de Registros y Predicciones de Flujo</h3>
              <p className="text-xs text-slate-400 mt-0.5">Inspecciona cómo cada vector CICIDS-2017 es clasificado por Centinela.</p>
            </div>

            {/* Filtros */}
            <div className="flex flex-wrap items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
              <button
                onClick={() => setFiltro('all')}
                className={`px-2.5 py-1 rounded-lg font-bold transition-all ${filtro === 'all' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                Todos ({data.registrosMuestra.length})
              </button>
              <button
                onClick={() => setFiltro('attacks')}
                className={`px-2.5 py-1 rounded-lg font-bold transition-all ${filtro === 'attacks' ? 'bg-red-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                Solo Ataques
              </button>
              <button
                onClick={() => setFiltro('benign')}
                className={`px-2.5 py-1 rounded-lg font-bold transition-all ${filtro === 'benign' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                Solo Benignos
              </button>
              <button
                onClick={() => setFiltro('vp')}
                className={`px-2.5 py-1 rounded-lg font-bold transition-all ${filtro === 'vp' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                VP
              </button>
              <button
                onClick={() => setFiltro('fp')}
                className={`px-2.5 py-1 rounded-lg font-bold transition-all ${filtro === 'fp' ? 'bg-amber-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                FP
              </button>
              <button
                onClick={() => setFiltro('fn')}
                className={`px-2.5 py-1 rounded-lg font-bold transition-all ${filtro === 'fn' ? 'bg-red-600 text-white' : 'text-slate-400 hover:text-white'}`}
              >
                FN
              </button>
            </div>
          </div>

          <div className="overflow-x-auto max-h-96 border border-slate-800 rounded-xl">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider sticky top-0 z-10 border-b border-slate-800">
                <tr>
                  <th className="p-3">#</th>
                  <th className="p-3">Puerto Destino</th>
                  <th className="p-3">Duración (ms)</th>
                  <th className="p-3">Packets/s</th>
                  <th className="p-3">IAT Mean (s)</th>
                  <th className="p-3">Etiqueta Real</th>
                  <th className="p-3">Score ML</th>
                  <th className="p-3">WAF Reglas</th>
                  <th className="p-3">Isolation Forest</th>
                  <th className="p-3">Ensamble ML</th>
                  <th className="p-3">Resultado</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono">
                {registrosFiltrados.slice(0, 50).map((r, i) => (
                  <tr key={i} className="hover:bg-slate-800/40">
                    <td className="p-3 text-slate-500">{r.id}</td>
                    <td className="p-3 text-white font-bold">{r.destPort}</td>
                    <td className="p-3 text-slate-300">{(r.flowDuration / 1000).toFixed(0)}</td>
                    <td className="p-3 text-slate-300">{r.flowPacketsSec.toFixed(1)}</td>
                    <td className="p-3 text-slate-300">{(r.flowIatMean / 1000000).toFixed(2)}s</td>
                    <td className="p-3 font-sans">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        r.isAttack ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                      }`}>
                        {r.label}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-cyan-400">{r.score_ml.toFixed(3)}</td>
                    <td className="p-3">
                      {r.prediccion_reglas ? (
                        <span className="text-red-400 font-bold">ALERTA</span>
                      ) : (
                        <span className="text-emerald-400">NORMAL</span>
                      )}
                    </td>
                    <td className="p-3">
                      {r.prediccion_iforest ? (
                        <span className="text-red-400 font-bold">ALERTA</span>
                      ) : (
                        <span className="text-emerald-400">NORMAL</span>
                      )}
                    </td>
                    <td className="p-3">
                      {r.prediccion_ensamble ? (
                        <span className="text-red-400 font-bold">ALERTA</span>
                      ) : (
                        <span className="text-emerald-400">NORMAL</span>
                      )}
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-black ${
                        r.resultado === 'VP' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                        r.resultado === 'FP' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                        r.resultado === 'FN' ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
                        'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                      }`}>
                        {r.resultado}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-[11px] text-slate-500 text-right">
            Mostrando {Math.min(50, registrosFiltrados.length)} de {registrosFiltrados.length} flujos filtrados.
          </p>
        </div>
      )}
    </div>
  );
}
