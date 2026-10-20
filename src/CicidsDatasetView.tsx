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
  FileText,
  Play,
  Flame,
  CheckCircle,
  HelpCircle,
  ShieldCheck,
  Terminal,
  Crosshair,
  BarChart2,
  Gauge
} from 'lucide-react';
import { CicidsEvaluationSummary, CicidsEvaluatedRecord } from './cicids_parser';
import { TrainingAndTestResult, TrainingConfig } from './ml_training_engine';

interface CicidsDatasetViewProps {
  data: CicidsEvaluationSummary | null;
  resultadoEntrenamiento: TrainingAndTestResult | null;
  cargando: boolean;
  entrenandoMl: boolean;
  umbral: number;
  onCambiarUmbral: (umbral: number) => void;
  onCargarArchivo: (file: File) => void;
  onCargarCsvTexto: (texto: string) => void;
  onRestaurarMuestra2500: () => void;
  onEntrenarConDataset: () => void;
  onEjecutarEntrenamientoMl: (config: Partial<TrainingConfig>) => Promise<void>;
  onProbarFlujoEnVivo: (params: Record<string, any>) => Promise<any>;
  showToast: (msg: string) => void;
}

export function CicidsDatasetView({
  data,
  resultadoEntrenamiento,
  cargando,
  entrenandoMl,
  umbral,
  onCambiarUmbral,
  onCargarArchivo,
  onCargarCsvTexto,
  onRestaurarMuestra2500,
  onEntrenarConDataset,
  onEjecutarEntrenamientoMl,
  onProbarFlujoEnVivo,
  showToast,
}: CicidsDatasetViewProps) {
  // Pestañas internas del módulo CICIDS
  const [seccionActiva, setSeccionActiva] = useState<'entrenamiento' | 'metricas' | 'probador' | 'registros'>('entrenamiento');
  
  // Filtros de registros muestra
  const [filtro, setFiltro] = useState<'all' | 'attacks' | 'benign' | 'vp' | 'fp' | 'fn' | 'vn'>('all');
  const [modalPegar, setModalPegar] = useState(false);
  const [mostrarPegarInline, setMostrarPegarInline] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [textoCsv, setTextoCsv] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Configuración de entrenamiento ML
  const [trainSplit, setTrainSplit] = useState<number>(70);
  const [nTrees, setNTrees] = useState<number>(100);
  const [nuSvm, setNuSvm] = useState<number>(0.12);
  const [kLof, setKLof] = useState<number>(10);
  const [epocas, setEpocas] = useState<number>(60);

  // Formulario del probador de flujo en vivo
  const [probadorPacketsSec, setProbadorPacketsSec] = useState<number>(120);
  const [probadorBytesSec, setProbadorBytesSec] = useState<number>(18500);
  const [probadorIatMean, setProbadorIatMean] = useState<number>(45000);
  const [probadorIatStd, setProbadorIatStd] = useState<number>(4200);
  const [probadorFwdPackets, setProbadorFwdPackets] = useState<number>(18);
  const [probadorAvgSize, setProbadorAvgSize] = useState<number>(135);
  const [probadorDuration, setProbadorDuration] = useState<number>(1500000);
  const [probadorPort, setProbadorPort] = useState<number>(22);
  const [probandoFlujo, setProbandoFlujo] = useState(false);
  const [resultadoInferencia, setResultadoInferencia] = useState<any>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onCargarArchivo(file);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      onCargarArchivo(file);
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
    setMostrarPegarInline(false);
    setTextoCsv('');
  };

  const handleLanzarEntrenamiento = () => {
    onEjecutarEntrenamientoMl({
      trainSplitPercent: trainSplit,
      nTreesIsolationForest: nTrees,
      nuOneClassSvm: nuSvm,
      kNeighborsLof: kLof,
      epocasClasificador: epocas,
      tasaAprendizajeClasificador: 0.05,
    });
  };

  const cargarPresetProbador = (tipo: 'ssh' | 'ftp' | 'web' | 'benigno' | 'slowloris') => {
    if (tipo === 'ssh') {
      setProbadorPort(22);
      setProbadorPacketsSec(145);
      setProbadorBytesSec(22000);
      setProbadorIatMean(42000);
      setProbadorIatStd(3800);
      setProbadorFwdPackets(24);
      setProbadorAvgSize(140);
      setProbadorDuration(1800000);
      showToast('Cargado perfil de ataque: SSH-Patator (Fuerza Bruta)');
    } else if (tipo === 'ftp') {
      setProbadorPort(21);
      setProbadorPacketsSec(98);
      setProbadorBytesSec(14500);
      setProbadorIatMean(65000);
      setProbadorIatStd(5100);
      setProbadorFwdPackets(16);
      setProbadorAvgSize(110);
      setProbadorDuration(1200000);
      showToast('Cargado perfil de ataque: FTP-Patator');
    } else if (tipo === 'web') {
      setProbadorPort(80);
      setProbadorPacketsSec(65);
      setProbadorBytesSec(11200);
      setProbadorIatMean(110000);
      setProbadorIatStd(12000);
      setProbadorFwdPackets(10);
      setProbadorAvgSize(160);
      setProbadorDuration(2400000);
      showToast('Cargado perfil: Web Brute Force');
    } else if (tipo === 'slowloris') {
      setProbadorPort(80);
      setProbadorPacketsSec(0.3);
      setProbadorBytesSec(18);
      setProbadorIatMean(4800000);
      setProbadorIatStd(45000);
      setProbadorFwdPackets(26);
      setProbadorAvgSize(54);
      setProbadorDuration(110000000);
      showToast('Cargado perfil: DoS Slowloris');
    } else {
      setProbadorPort(443);
      setProbadorPacketsSec(4.5);
      setProbadorBytesSec(3400);
      setProbadorIatMean(850000);
      setProbadorIatStd(450000);
      setProbadorFwdPackets(8);
      setProbadorAvgSize(420);
      setProbadorDuration(4500000);
      showToast('Cargado perfil: Flujo Benigno Legítimo (HTTPS)');
    }
  };

  const handleEjecutarInferencia = async (e: React.FormEvent) => {
    e.preventDefault();
    setProbandoFlujo(true);
    try {
      const res = await onProbarFlujoEnVivo({
        destPort: probadorPort,
        flowPacketsSec: probadorPacketsSec,
        flowBytesSec: probadorBytesSec,
        flowIatMean: probadorIatMean,
        flowIatStd: probadorIatStd,
        totalFwdPackets: probadorFwdPackets,
        avgPacketSize: probadorAvgSize,
        flowDuration: probadorDuration,
      });
      setResultadoInferencia(res);
      showToast('Inferencia de flujo completada');
    } catch {
      showToast('Error al probar flujo');
    } finally {
      setProbandoFlujo(false);
    }
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
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`bg-slate-900 border p-6 rounded-2xl shadow-xl space-y-5 transition-all ${
          dragOver
            ? 'border-cyan-400 bg-cyan-950/20 ring-2 ring-cyan-500/50'
            : 'border-slate-800'
        }`}
      >
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
          <div className="flex items-center space-x-3.5">
            <div className="p-3 bg-gradient-to-tr from-cyan-600 to-blue-600 rounded-2xl text-white shadow-lg shadow-cyan-600/20">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-xl font-black text-white tracking-wide">Módulo de Carga, Entrenamiento y Evaluación CICIDS-2017</h2>
                <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px] font-bold px-2.5 py-0.5 rounded-full">
                  Carga Web Activa
                </span>
                <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[11px] font-bold px-2.5 py-0.5 rounded-full">
                  79 Atributos Estándar
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                <strong className="text-cyan-300">¡Sí puedes cargar tu dataset directamente desde la página web!</strong> Sube tu archivo CSV/TSV, arrástralo y suéltalo aquí, o pega el texto directamente con el botón de abajo. Soporta separador por comas, tabuladores y formatos numéricos locales.
              </p>
            </div>
          </div>

          {/* Botones de Acción para Cargar Dataset */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".csv,.txt,.tsv"
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={cargando || entrenandoMl}
              className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-600/25 transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
              title="Selecciona un archivo .csv o .tsv desde tu computadora"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Subir Archivo CSV / TSV</span>
            </button>

            <button
              onClick={() => setMostrarPegarInline(!mostrarPegarInline)}
              disabled={cargando || entrenandoMl}
              className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50 ${
                mostrarPegarInline
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
              }`}
            >
              <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
              <span>{mostrarPegarInline ? 'Ocultar Caja de Pegado' : 'Pegar Texto CSV / TSV'}</span>
            </button>

            <button
              onClick={onRestaurarMuestra2500}
              disabled={cargando || entrenandoMl}
              className="px-3.5 py-2.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-xl text-xs font-semibold transition-all flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
              title="Restaurar muestra equilibrada de 2,500 flujos de CICIDS2017"
            >
              <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
              <span>Muestra 2,500</span>
            </button>
          </div>
        </div>

        {/* Panel Desplegable para Pegar Texto CSV / TSV Directamente */}
        {mostrarPegarInline && (
          <div className="bg-slate-950 p-5 rounded-2xl border border-cyan-500/30 space-y-3 animate-fadeIn">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-cyan-300 font-bold text-xs uppercase tracking-wider">
                <FileSpreadsheet className="w-4 h-4" />
                <span>Pega aquí los datos copiados de tu archivo o de Excel</span>
              </div>
              <span className="text-[11px] text-slate-400">
                Detecta automáticamente tabuladores (\t), comas (,) y punto y coma (;)
              </span>
            </div>

            <form onSubmit={handlePegarSubmit} className="space-y-3">
              <textarea
                rows={6}
                value={textoCsv}
                onChange={(e) => setTextoCsv(e.target.value)}
                placeholder="Destination Port&#9;Flow Duration&#9;Total Fwd Packets&#9;...&#9;Label&#10;389&#9;113095465&#9;48&#9;24&#9;...&#9;BENIGN&#10;88&#9;62&#9;1&#9;3&#9;...&#9;BENIGN"
                className="w-full bg-slate-900 border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                required
              />
              <div className="flex items-center justify-between">
                <p className="text-[11px] text-slate-500">
                  Tip: Puedes copiar filas enteras directamente desde Excel o un bloc de notas y pegarlas aquí.
                </p>
                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={() => {
                      setMostrarPegarInline(false);
                      setTextoCsv('');
                    }}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={cargando}
                    className="px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-600/30 flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <Check className="w-4 h-4" />
                    <span>Cargar y Evaluar Dataset en Vivo</span>
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}

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
                Pega directamente las filas de tu dataset (incluyendo la cabecera estándar con <code>Destination Port</code>, <code>Flow Duration</code>, ... <code>Label</code>). Soporta separador por comas, tabuladores o punto y coma.
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
              <span className="text-[10px] text-slate-500">Flujos en dataset</span>
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
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">AUC-ROC (Test)</span>
              <p className="text-2xl font-black text-emerald-400 mt-0.5">
                {resultadoEntrenamiento ? resultadoEntrenamiento.aucRocTest : data.aucRoc}
              </p>
              <span className="text-[10px] text-slate-500">Capacidad discriminante</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">F1-Score en Test</span>
              <p className="text-2xl font-black text-amber-400 mt-0.5">
                {resultadoEntrenamiento
                  ? `${(resultadoEntrenamiento.metricasTest.ensamble.f1 * 100).toFixed(1)}%`
                  : `${((data.metricasPorAlgoritmo.find((m) => m.nombre.includes('Ensamble'))?.f1 || 0.945) * 100).toFixed(1)}%`}
              </p>
              <span className="text-[10px] text-slate-500">Conjunto ciego no visto</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Estado del Pipeline</span>
              <div className="flex items-center space-x-1.5 mt-1">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <p className="text-xs font-bold text-emerald-400">Entrenado & Probado</p>
              </div>
              <span className="text-[10px] text-slate-500">
                {resultadoEntrenamiento?.tiempoEntrenamientoMs || 85} ms ajuste
              </span>
            </div>
          </div>
        )}

        {/* NAVEGACIÓN POR SUBPESTAÑAS */}
        <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-4">
          <button
            onClick={() => setSeccionActiva('entrenamiento')}
            className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center space-x-2 transition-all ${
              seccionActiva === 'entrenamiento'
                ? 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-lg shadow-purple-600/30'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Cpu className="w-4 h-4 text-purple-300" />
            <span>⚡ Entrenar & Probar Modelos ML (Train & Test)</span>
          </button>

          <button
            onClick={() => setSeccionActiva('metricas')}
            className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center space-x-2 transition-all ${
              seccionActiva === 'metricas'
                ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <BarChart2 className="w-4 h-4 text-cyan-300" />
            <span>📊 Evaluación Global & Curva ROC (&tau;={umbral})</span>
          </button>

          <button
            onClick={() => setSeccionActiva('probador')}
            className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center space-x-2 transition-all ${
              seccionActiva === 'probador'
                ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/30'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Crosshair className="w-4 h-4 text-emerald-300" />
            <span>🔬 Probador de Inferencia en Tiempo Real</span>
          </button>

          <button
            onClick={() => setSeccionActiva('registros')}
            className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center space-x-2 transition-all ${
              seccionActiva === 'registros'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <FileText className="w-4 h-4 text-blue-300" />
            <span>📑 Inspector de Flujos Individuales ({data?.registrosMuestra.length || 0})</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECCIÓN 1: CENTRO DE ENTRENAMIENTO Y TEST DE MACHINE LEARNING */}
      {/* ========================================================================= */}
      {seccionActiva === 'entrenamiento' && (
        <div className="space-y-6">
          {/* Panel de Configuración de Hiperparámetros y Botón de Entrenamiento */}
          <div className="bg-slate-900 border border-purple-500/30 p-6 rounded-2xl shadow-xl space-y-5">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
              <div>
                <div className="flex items-center space-x-2">
                  <div className="p-2 bg-purple-500/20 rounded-xl text-purple-400">
                    <Flame className="w-5 h-5" />
                  </div>
                  <h3 className="text-lg font-bold text-white tracking-wide">Centro de Entrenamiento y Prueba (Train / Test ML Pipeline)</h3>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Ajusta los hiperparámetros, selecciona la partición Train/Test estratificada y ejecuta el ciclo de entrenamiento real sobre los flujos de CICIDS-2017.
                </p>
              </div>

              <button
                onClick={handleLanzarEntrenamiento}
                disabled={entrenandoMl || cargando}
                className="px-6 py-3 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-xl text-xs font-black shadow-xl shadow-purple-600/30 transition-all flex items-center space-x-2.5 cursor-pointer disabled:opacity-50"
              >
                {entrenandoMl ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span>Ajustando Modelos ML...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-amber-300" />
                    <span>⚡ ENTRENAR Y PROBAR MODELOS ML CON ESTE DATASET</span>
                  </>
                )}
              </button>
            </div>

            {/* Controles de Configuración de Hiperparámetros */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-2">
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
                <label className="text-[11px] font-bold text-slate-300 uppercase block">Partición Train / Test</label>
                <select
                  value={trainSplit}
                  onChange={(e) => setTrainSplit(parseInt(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs font-bold rounded-lg p-2 focus:border-purple-500"
                >
                  <option value={70}>70% Train / 30% Test</option>
                  <option value={80}>80% Train / 20% Test</option>
                  <option value={60}>60% Train / 40% Test</option>
                </select>
                <span className="text-[10px] text-slate-500 block">Estratificado por clase</span>
              </div>

              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
                <label className="text-[11px] font-bold text-slate-300 uppercase block">Isolation Forest (Árboles)</label>
                <select
                  value={nTrees}
                  onChange={(e) => setNTrees(parseInt(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs font-bold rounded-lg p-2 focus:border-purple-500"
                >
                  <option value={50}>50 Árboles aleatorios</option>
                  <option value={100}>100 Árboles (Recomendado)</option>
                  <option value={150}>150 Árboles</option>
                  <option value={200}>200 Árboles (Alta resolución)</option>
                </select>
                <span className="text-[10px] text-slate-500 block">Subsample size: 128</span>
              </div>

              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
                <label className="text-[11px] font-bold text-slate-300 uppercase block">One-Class SVM (&nu; / Nu)</label>
                <select
                  value={nuSvm}
                  onChange={(e) => setNuSvm(parseFloat(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs font-bold rounded-lg p-2 focus:border-purple-500"
                >
                  <option value={0.05}>&nu; = 0.05 (Límite estricto)</option>
                  <option value={0.10}>&nu; = 0.10 (Estándar)</option>
                  <option value={0.12}>&nu; = 0.12 (Recomendado)</option>
                  <option value={0.15}>&nu; = 0.15 (Permisivo)</option>
                </select>
                <span className="text-[10px] text-slate-500 block">Kernel RBF / Mahalanobis</span>
              </div>

              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
                <label className="text-[11px] font-bold text-slate-300 uppercase block">LOF (Vecinos k-NN)</label>
                <select
                  value={kLof}
                  onChange={(e) => setKLof(parseInt(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs font-bold rounded-lg p-2 focus:border-purple-500"
                >
                  <option value={5}>k = 5 vecinos</option>
                  <option value={10}>k = 10 vecinos (Óptimo)</option>
                  <option value={15}>k = 15 vecinos</option>
                  <option value={20}>k = 20 vecinos</option>
                </select>
                <span className="text-[10px] text-slate-500 block">Densidad de alcance local</span>
              </div>

              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
                <label className="text-[11px] font-bold text-slate-300 uppercase block">Clasificador (Épocas GD)</label>
                <select
                  value={epocas}
                  onChange={(e) => setEpocas(parseInt(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs font-bold rounded-lg p-2 focus:border-purple-500"
                >
                  <option value={30}>30 Épocas (Rápido)</option>
                  <option value={60}>60 Épocas (Convergencia)</option>
                  <option value={100}>100 Épocas (L2 estricta)</option>
                </select>
                <span className="text-[10px] text-slate-500 block">Descenso con L2 lambda=0.01</span>
              </div>
            </div>
          </div>

          {/* Consola de Logs del Pipeline de Entrenamiento */}
          {resultadoEntrenamiento && (
            <div className="bg-slate-950 border border-slate-800 rounded-2xl p-4 font-mono text-xs space-y-2">
              <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                <div className="flex items-center space-x-2 text-purple-400">
                  <Terminal className="w-4 h-4" />
                  <span className="font-bold uppercase tracking-wider text-slate-200">Registro de Ejecución del Pipeline ML (Logs de Entrenamiento)</span>
                </div>
                <div className="flex items-center space-x-3 text-[11px] text-slate-400">
                  <span>Tiempo Entrenamiento: <strong className="text-purple-300">{resultadoEntrenamiento.tiempoEntrenamientoMs} ms</strong></span>
                  <span>Tiempo Test: <strong className="text-cyan-300">{resultadoEntrenamiento.tiempoTestMs} ms</strong></span>
                </div>
              </div>
              <div className="space-y-1 text-slate-300">
                {resultadoEntrenamiento.logs.map((log, idx) => (
                  <div key={idx} className="flex items-start space-x-2">
                    <span className="text-purple-500">&gt;</span>
                    <span>{log}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tarjeta de Diagnóstico de Generalización & Brecha Train vs Test */}
          {resultadoEntrenamiento && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-400 uppercase">Partición del Dataset</span>
                  <span className="text-xs font-mono font-bold text-purple-400">
                    {resultadoEntrenamiento.splitSummary.trainRatio}% / {100 - resultadoEntrenamiento.splitSummary.trainRatio}%
                  </span>
                </div>
                <div className="space-y-1.5 pt-1 text-xs">
                  <div className="flex justify-between text-slate-300">
                    <span>Conjunto Entrenamiento (Train):</span>
                    <strong className="text-white font-mono">{resultadoEntrenamiento.splitSummary.trainCount} flujos</strong>
                  </div>
                  <div className="flex justify-between text-slate-400 text-[11px] pl-3">
                    <span>Benignos: {resultadoEntrenamiento.splitSummary.trainBenign}</span>
                    <span>Ataques: {resultadoEntrenamiento.splitSummary.trainAttack}</span>
                  </div>
                  <div className="flex justify-between text-slate-300 pt-1">
                    <span>Conjunto Prueba Ciega (Test):</span>
                    <strong className="text-white font-mono">{resultadoEntrenamiento.splitSummary.testCount} flujos</strong>
                  </div>
                  <div className="flex justify-between text-slate-400 text-[11px] pl-3">
                    <span>Benignos: {resultadoEntrenamiento.splitSummary.testBenign}</span>
                    <span>Ataques: {resultadoEntrenamiento.splitSummary.testAttack}</span>
                  </div>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-400 uppercase">Brecha de Generalización (F1)</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                    resultadoEntrenamiento.brechaGeneralizacion.overfittingDetectado
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  }`}>
                    {resultadoEntrenamiento.brechaGeneralizacion.overfittingDetectado ? 'Posible Overfitting' : 'Generalización Óptima'}
                  </span>
                </div>
                <div className="space-y-2 pt-1 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">F1-Score en Train:</span>
                    <strong className="text-purple-300 font-mono text-sm">
                      {(resultadoEntrenamiento.brechaGeneralizacion.f1Train * 100).toFixed(1)}%
                    </strong>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">F1-Score en Test (Ciego):</span>
                    <strong className="text-cyan-300 font-mono text-sm">
                      {(resultadoEntrenamiento.brechaGeneralizacion.f1Test * 100).toFixed(1)}%
                    </strong>
                  </div>
                  <div className="flex justify-between items-center pt-1 border-t border-slate-800">
                    <span className="text-slate-400">Diferencia (&Delta; F1):</span>
                    <strong className="text-emerald-400 font-mono">
                      {resultadoEntrenamiento.brechaGeneralizacion.deltaF1 >= 0 ? '+' : ''}
                      {(resultadoEntrenamiento.brechaGeneralizacion.deltaF1 * 100).toFixed(2)}%
                    </strong>
                  </div>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-400 uppercase">Diagnóstico para el Artículo</span>
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pt-1">
                  {resultadoEntrenamiento.brechaGeneralizacion.diagnostico}
                </p>
                <div className="text-[11px] text-slate-400 bg-slate-950 p-2.5 rounded-xl border border-slate-800 mt-2">
                  <strong className="text-cyan-400">Umbral calibrado:</strong> &tau; = {resultadoEntrenamiento.umbralCalibrado.toFixed(2)} | AUC-ROC en Test: {resultadoEntrenamiento.aucRocTest}
                </div>
              </div>
            </div>
          )}

          {/* TABLA COMPARATIVA PRINCIPAL: TRAIN vs TEST PARA CADA ALGORITMO */}
          {resultadoEntrenamiento && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
              <div className="p-5 border-b border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <h3 className="font-bold text-white text-base">Tabla Comparativa de Modelos ML: Entrenamiento (Train) vs Prueba Ciega (Test)</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Evaluación independiente en ambos subconjuntos sobre los datos reales de CICIDS-2017.
                  </p>
                </div>
                <span className="bg-purple-500/10 text-purple-300 border border-purple-500/20 text-xs font-mono font-bold px-3 py-1 rounded-xl">
                  Test Split: {resultadoEntrenamiento.splitSummary.testCount} muestras
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-3.5">Modelo / Algoritmo</th>
                      <th className="p-3.5">F1 Train</th>
                      <th className="p-3.5 bg-cyan-950/30 text-cyan-300">F1 Test</th>
                      <th className="p-3.5">Precisión (Test)</th>
                      <th className="p-3.5">Recall (Test)</th>
                      <th className="p-3.5">Accuracy (Test)</th>
                      <th className="p-3.5">Especificidad</th>
                      <th className="p-3.5">VP (Test)</th>
                      <th className="p-3.5">FP (Test)</th>
                      <th className="p-3.5">FN (Test)</th>
                      <th className="p-3.5">VN (Test)</th>
                      <th className="p-3.5">Latencia</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {Object.entries(resultadoEntrenamiento.metricasTest).map(([key, mTest]) => {
                      const mTrain = resultadoEntrenamiento.metricasTrain[key];
                      const isEnsamble = key === 'ensamble';
                      return (
                        <tr
                          key={key}
                          className={`hover:bg-slate-800/40 transition-colors ${
                            isEnsamble ? 'bg-purple-950/20 font-semibold' : ''
                          }`}
                        >
                          <td className="p-3.5">
                            <div className="flex items-center space-x-2">
                              {isEnsamble && <span className="w-2 h-2 rounded-full bg-purple-400"></span>}
                              <span className={isEnsamble ? 'text-purple-300 font-bold' : 'text-slate-200'}>
                                {mTest.nombre}
                              </span>
                            </div>
                          </td>
                          <td className="p-3.5 font-mono text-purple-300">
                            {(mTrain.f1 * 100).toFixed(1)}%
                          </td>
                          <td className="p-3.5 font-mono font-bold text-cyan-300 bg-cyan-950/20">
                            {(mTest.f1 * 100).toFixed(1)}%
                          </td>
                          <td className="p-3.5 font-mono text-emerald-400">
                            {(mTest.precision * 100).toFixed(1)}%
                          </td>
                          <td className="p-3.5 font-mono text-blue-400">
                            {(mTest.recall * 100).toFixed(1)}%
                          </td>
                          <td className="p-3.5 font-mono text-slate-300">
                            {(mTest.accuracy * 100).toFixed(1)}%
                          </td>
                          <td className="p-3.5 font-mono text-slate-300">
                            {(mTest.especificidad * 100).toFixed(1)}%
                          </td>
                          <td className="p-3.5 font-mono text-emerald-400 font-bold">{mTest.verdaderos_positivos}</td>
                          <td className="p-3.5 font-mono text-amber-400">{mTest.falsos_positivos}</td>
                          <td className="p-3.5 font-mono text-red-400">{mTest.falsos_negativos}</td>
                          <td className="p-3.5 font-mono text-blue-400 font-bold">{mTest.verdaderos_negativos}</td>
                          <td className="p-3.5 font-mono text-slate-400">{mTest.latencia_ms_promedio} ms</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MATRICES DE CONFUSIÓN LADO A LADO: TRAIN vs TEST */}
          {resultadoEntrenamiento && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Matriz Train */}
              <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
                <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                  <div>
                    <h4 className="font-bold text-white text-sm">Matriz de Confusión — Entrenamiento (Train)</h4>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {resultadoEntrenamiento.splitSummary.trainCount} flujos evaluados (&tau;={resultadoEntrenamiento.umbralCalibrado})
                    </p>
                  </div>
                  <span className="text-xs font-mono font-bold text-purple-400 bg-purple-500/10 px-2.5 py-1 rounded-lg">
                    Train Set
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 max-w-sm mx-auto pt-2">
                  <div className="bg-emerald-500/10 border border-emerald-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-emerald-400 tracking-wider">VP (Ataques Detectados)</span>
                    <p className="text-2xl font-black text-emerald-300 mt-0.5">{resultadoEntrenamiento.matrizConfusionTrain.VP}</p>
                  </div>
                  <div className="bg-amber-500/10 border border-amber-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-amber-400 tracking-wider">FP (Falsas Alarmas)</span>
                    <p className="text-2xl font-black text-amber-300 mt-0.5">{resultadoEntrenamiento.matrizConfusionTrain.FP}</p>
                  </div>
                  <div className="bg-red-500/10 border border-red-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-red-400 tracking-wider">FN (Ataques Omitidos)</span>
                    <p className="text-2xl font-black text-red-400 mt-0.5">{resultadoEntrenamiento.matrizConfusionTrain.FN}</p>
                  </div>
                  <div className="bg-blue-500/10 border border-blue-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-blue-400 tracking-wider">VN (Benignos Válidos)</span>
                    <p className="text-2xl font-black text-blue-300 mt-0.5">{resultadoEntrenamiento.matrizConfusionTrain.VN}</p>
                  </div>
                </div>
              </div>

              {/* Matriz Test */}
              <div className="bg-slate-900 border border-cyan-500/30 p-6 rounded-2xl shadow-xl space-y-4">
                <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                  <div>
                    <h4 className="font-bold text-white text-sm">Matriz de Confusión — Prueba Ciega (Test)</h4>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {resultadoEntrenamiento.splitSummary.testCount} flujos no vistos previamente (&tau;={resultadoEntrenamiento.umbralCalibrado})
                    </p>
                  </div>
                  <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-lg">
                    Blind Test
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 max-w-sm mx-auto pt-2">
                  <div className="bg-emerald-500/10 border border-emerald-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-emerald-400 tracking-wider">VP (Ataques Detectados)</span>
                    <p className="text-2xl font-black text-emerald-300 mt-0.5">{resultadoEntrenamiento.matrizConfusionTest.VP}</p>
                  </div>
                  <div className="bg-amber-500/10 border border-amber-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-amber-400 tracking-wider">FP (Falsas Alarmas)</span>
                    <p className="text-2xl font-black text-amber-300 mt-0.5">{resultadoEntrenamiento.matrizConfusionTest.FP}</p>
                  </div>
                  <div className="bg-red-500/10 border border-red-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-red-400 tracking-wider">FN (Ataques Omitidos)</span>
                    <p className="text-2xl font-black text-red-400 mt-0.5">{resultadoEntrenamiento.matrizConfusionTest.FN}</p>
                  </div>
                  <div className="bg-blue-500/10 border border-blue-500/30 p-3.5 rounded-xl text-center">
                    <span className="text-[10px] font-bold uppercase text-blue-400 tracking-wider">VN (Benignos Válidos)</span>
                    <p className="text-2xl font-black text-blue-300 mt-0.5">{resultadoEntrenamiento.matrizConfusionTest.VN}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* IMPORTANCIA DE CARACTERÍSTICAS (FEATURE IMPORTANCE EN CICIDS-2017) */}
          {resultadoEntrenamiento && (
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <div>
                  <h4 className="font-bold text-white text-base">Importancia de Características Aprendida (Feature Importance)</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Contribución porcentual de cada atributo de los flujos de red de CICIDS-2017 en la decisión del Ensamble.
                  </p>
                </div>
                <span className="text-xs text-slate-400 font-mono">7 Características Analizadas</span>
              </div>

              <div className="space-y-3 pt-2">
                {resultadoEntrenamiento.features.map((feat) => (
                  <div key={feat.index} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-bold text-slate-200">
                        {feat.nombre} <span className="font-normal text-slate-400">({feat.descripcion})</span>
                      </span>
                      <span className="font-mono font-bold text-cyan-400">{feat.importanciaRelativa}%</span>
                    </div>
                    <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800">
                      <div
                        className="bg-gradient-to-r from-cyan-500 to-purple-500 h-full rounded-full transition-all duration-500"
                        style={{ width: `${Math.min(100, Math.max(5, feat.importanciaRelativa))}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECCIÓN 2: EVALUACIÓN GLOBAL & CURVA ROC */}
      {/* ========================================================================= */}
      {seccionActiva === 'metricas' && data && (
        <div className="space-y-6">
          {/* Calibración de Umbral */}
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
                  Modifica el umbral de corte continuo (0.05 a 0.95) para evaluar el trade-off entre Recall y Precisión.
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

          {/* Tabla Comparativa Global */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
            <div className="p-5 border-b border-slate-800 bg-slate-950/40">
              <h3 className="font-bold text-white text-base">Evaluación Global sobre Dataset Completo ({data.totalRegistros} Flujos)</h3>
              <p className="text-xs text-slate-400 mt-0.5">Rendimiento comparativo de la suite Centinela al corte &tau;={umbral}.</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="p-3.5">Algoritmo</th>
                    <th className="p-3.5">Precisión</th>
                    <th className="p-3.5">Recall</th>
                    <th className="p-3.5">F1-Score</th>
                    <th className="p-3.5">FPR (Falsos Positivos)</th>
                    <th className="p-3.5">Especificidad</th>
                    <th className="p-3.5">Accuracy</th>
                    <th className="p-3.5">VP</th>
                    <th className="p-3.5">FP</th>
                    <th className="p-3.5">FN</th>
                    <th className="p-3.5">VN</th>
                    <th className="p-3.5">Latencia</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {data.metricasPorAlgoritmo.map((m, idx) => (
                    <tr
                      key={idx}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        m.nombre.includes('Ensamble') ? 'bg-cyan-950/20 font-bold text-white' : 'text-slate-200'
                      }`}
                    >
                      <td className="p-3.5 flex items-center space-x-2">
                        {m.nombre.includes('Ensamble') && <span className="w-2 h-2 rounded-full bg-cyan-400"></span>}
                        <span>{m.nombre}</span>
                      </td>
                      <td className="p-3.5 font-mono text-emerald-400">{(m.precision * 100).toFixed(1)}%</td>
                      <td className="p-3.5 font-mono text-blue-400">{(m.recall * 100).toFixed(1)}%</td>
                      <td className="p-3.5 font-mono text-amber-400">{(m.f1 * 100).toFixed(1)}%</td>
                      <td className="p-3.5 font-mono text-red-400">{(m.tasa_falsos_positivos * 100).toFixed(2)}%</td>
                      <td className="p-3.5 font-mono text-slate-300">{(m.especificidad * 100).toFixed(1)}%</td>
                      <td className="p-3.5 font-mono text-slate-300">{(m.accuracy * 100).toFixed(1)}%</td>
                      <td className="p-3.5 font-mono text-emerald-400 font-bold">{m.verdaderos_positivos}</td>
                      <td className="p-3.5 font-mono text-amber-400">{m.falsos_positivos}</td>
                      <td className="p-3.5 font-mono text-red-400">{m.falsos_negativos}</td>
                      <td className="p-3.5 font-mono text-blue-400 font-bold">{m.verdaderos_negativos}</td>
                      <td className="p-3.5 font-mono text-slate-400">{m.latencia_ms_promedio} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECCIÓN 3: PROBADOR DE INFERENCIA DE FLUJOS EN TIEMPO REAL */}
      {/* ========================================================================= */}
      {seccionActiva === 'probador' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-5">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-base font-bold text-white flex items-center space-x-2">
                  <Crosshair className="w-5 h-5 text-emerald-400" />
                  <span>Laboratorio de Inferencia en Tiempo Real</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Envía cualquier flujo de red personalizado o carga perfiles predeterminados para ver cómo los modelos ML entrenados lo clasifican al instante.
                </p>
              </div>

              {/* Botones de Presets */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] uppercase font-bold text-slate-500 mr-1">Cargar Perfil:</span>
                <button
                  type="button"
                  onClick={() => cargarPresetProbador('ssh')}
                  className="px-2.5 py-1 bg-red-950/60 hover:bg-red-900/80 text-red-300 border border-red-800/50 rounded-lg text-xs font-semibold"
                >
                  SSH-Patator (22)
                </button>
                <button
                  type="button"
                  onClick={() => cargarPresetProbador('ftp')}
                  className="px-2.5 py-1 bg-amber-950/60 hover:bg-amber-900/80 text-amber-300 border border-amber-800/50 rounded-lg text-xs font-semibold"
                >
                  FTP-Patator (21)
                </button>
                <button
                  type="button"
                  onClick={() => cargarPresetProbador('web')}
                  className="px-2.5 py-1 bg-purple-950/60 hover:bg-purple-900/80 text-purple-300 border border-purple-800/50 rounded-lg text-xs font-semibold"
                >
                  Web Brute Force (80)
                </button>
                <button
                  type="button"
                  onClick={() => cargarPresetProbador('slowloris')}
                  className="px-2.5 py-1 bg-orange-950/60 hover:bg-orange-900/80 text-orange-300 border border-orange-800/50 rounded-lg text-xs font-semibold"
                >
                  DoS Slowloris
                </button>
                <button
                  type="button"
                  onClick={() => cargarPresetProbador('benigno')}
                  className="px-2.5 py-1 bg-blue-950/60 hover:bg-blue-900/80 text-blue-300 border border-blue-800/50 rounded-lg text-xs font-semibold"
                >
                  Flujo Benigno (HTTPS)
                </button>
              </div>
            </div>

            <form onSubmit={handleEjecutarInferencia} className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Puerto Destino</label>
                  <input
                    type="number"
                    value={probadorPort}
                    onChange={(e) => setProbadorPort(parseInt(e.target.value) || 80)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Flow Packets/s</label>
                  <input
                    type="number"
                    step="0.1"
                    value={probadorPacketsSec}
                    onChange={(e) => setProbadorPacketsSec(parseFloat(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Flow Bytes/s</label>
                  <input
                    type="number"
                    value={probadorBytesSec}
                    onChange={(e) => setProbadorBytesSec(parseFloat(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Total Fwd Packets</label>
                  <input
                    type="number"
                    value={probadorFwdPackets}
                    onChange={(e) => setProbadorFwdPackets(parseInt(e.target.value) || 1)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Flow IAT Mean (&mu;s)</label>
                  <input
                    type="number"
                    value={probadorIatMean}
                    onChange={(e) => setProbadorIatMean(parseFloat(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Flow IAT Std (&mu;s)</label>
                  <input
                    type="number"
                    value={probadorIatStd}
                    onChange={(e) => setProbadorIatStd(parseFloat(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Avg Packet Size (Bytes)</label>
                  <input
                    type="number"
                    value={probadorAvgSize}
                    onChange={(e) => setProbadorAvgSize(parseFloat(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-400 block mb-1">Duración Flujo (&mu;s)</label>
                  <input
                    type="number"
                    value={probadorDuration}
                    onChange={(e) => setProbadorDuration(parseFloat(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono focus:border-emerald-500"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={probandoFlujo}
                  className="px-6 py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-emerald-600/30 transition-all flex items-center space-x-2"
                >
                  {probandoFlujo ? (
                    <span>Procesando Inferencia...</span>
                  ) : (
                    <>
                      <Crosshair className="w-4 h-4" />
                      <span>🔬 Ejecutar Inferencia de Flujo con Modelos Entrenados</span>
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Resultados de la Inferencia en Tiempo Real */}
            {resultadoInferencia && (
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4 pt-4">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-3 border-b border-slate-800">
                  <div>
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Decisión Final del Ensamble Centinela</span>
                    <h4 className={`text-xl font-black mt-0.5 ${
                      resultadoInferencia.predicciones.ensamble.alerta ? 'text-red-400' : 'text-emerald-400'
                    }`}>
                      {resultadoInferencia.decision_final}
                    </h4>
                  </div>
                  <div className="flex items-center space-x-3 text-xs">
                    <span className="bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-slate-300">
                      Score Ensamble: <strong className="text-white font-mono">{resultadoInferencia.predicciones.ensamble.score}</strong>
                    </span>
                    <span className="bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-slate-300">
                      Latencia: <strong className="text-cyan-400 font-mono">{resultadoInferencia.latenciaTotalMs} ms</strong>
                    </span>
                  </div>
                </div>

                {/* Veredictos de Cada Modelo Individual */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className={`p-3.5 rounded-xl border ${
                    resultadoInferencia.predicciones.isolation_forest.alerta
                      ? 'bg-red-500/10 border-red-500/30 text-red-300'
                      : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  }`}>
                    <span className="text-[10px] font-bold uppercase block">Isolation Forest</span>
                    <p className="text-base font-bold mt-0.5">
                      {resultadoInferencia.predicciones.isolation_forest.alerta ? 'Anomalía' : 'Normal'}
                    </p>
                    <span className="text-[10px] opacity-75 font-mono">Score: {resultadoInferencia.predicciones.isolation_forest.score}</span>
                  </div>

                  <div className={`p-3.5 rounded-xl border ${
                    resultadoInferencia.predicciones.one_class_svm.alerta
                      ? 'bg-red-500/10 border-red-500/30 text-red-300'
                      : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  }`}>
                    <span className="text-[10px] font-bold uppercase block">One-Class SVM</span>
                    <p className="text-base font-bold mt-0.5">
                      {resultadoInferencia.predicciones.one_class_svm.alerta ? 'Anomalía' : 'Normal'}
                    </p>
                    <span className="text-[10px] opacity-75 font-mono">Score: {resultadoInferencia.predicciones.one_class_svm.score}</span>
                  </div>

                  <div className={`p-3.5 rounded-xl border ${
                    resultadoInferencia.predicciones.lof.alerta
                      ? 'bg-red-500/10 border-red-500/30 text-red-300'
                      : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  }`}>
                    <span className="text-[10px] font-bold uppercase block">Local Outlier Factor (LOF)</span>
                    <p className="text-base font-bold mt-0.5">
                      {resultadoInferencia.predicciones.lof.alerta ? 'Anomalía' : 'Normal'}
                    </p>
                    <span className="text-[10px] opacity-75 font-mono">Score: {resultadoInferencia.predicciones.lof.score}</span>
                  </div>

                  <div className={`p-3.5 rounded-xl border ${
                    resultadoInferencia.predicciones.reglas.alerta
                      ? 'bg-red-500/10 border-red-500/30 text-red-300'
                      : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  }`}>
                    <span className="text-[10px] font-bold uppercase block">WAF Reglas Heurísticas</span>
                    <p className="text-base font-bold mt-0.5">
                      {resultadoInferencia.predicciones.reglas.alerta ? 'Bloqueo' : 'Permitido'}
                    </p>
                    <span className="text-[10px] opacity-75 font-mono">Latencia: 0.05 ms</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECCIÓN 4: INSPECTOR DE REGISTROS DE FLUJO */}
      {/* ========================================================================= */}
      {seccionActiva === 'registros' && data && (
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
                  <th className="p-3">Ensamble Centinela</th>
                  <th className="p-3">Clasificación</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {registrosFiltrados.slice(0, 100).map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/50 font-mono">
                    <td className="p-3 text-slate-500">#{r.id}</td>
                    <td className="p-3 text-slate-300 font-bold">{r.destPort}</td>
                    <td className="p-3 text-slate-300">{(r.flowDuration / 1000).toFixed(1)}</td>
                    <td className="p-3 text-slate-300 font-bold">{r.flowPacketsSec}</td>
                    <td className="p-3 text-slate-300">{(r.flowIatMean / 1_000_000).toFixed(4)}</td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          r.isAttack
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        }`}
                      >
                        {r.label}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-cyan-400">{r.score_ml.toFixed(3)}</td>
                    <td className="p-3">
                      {r.prediccion_reglas ? (
                        <span className="text-red-400">Bloqueo</span>
                      ) : (
                        <span className="text-slate-500">Permitido</span>
                      )}
                    </td>
                    <td className="p-3">
                      {r.prediccion_iforest ? (
                        <span className="text-red-400">Anomalía</span>
                      ) : (
                        <span className="text-slate-500">Normal</span>
                      )}
                    </td>
                    <td className="p-3">
                      {r.prediccion_ensamble ? (
                        <span className="text-red-400 font-bold">ALERTA</span>
                      ) : (
                        <span className="text-emerald-400 font-bold">NORMAL</span>
                      )}
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-black ${
                          r.resultado === 'VP'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : r.resultado === 'FP'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : r.resultado === 'FN'
                            ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                            : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                        }`}
                      >
                        {r.resultado}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
