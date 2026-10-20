import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import {
  Shield,
  Activity,
  AlertTriangle,
  Play,
  RotateCcw,
  Download,
  Terminal,
  BarChart2,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  Cpu,
  Database,
  Sliders,
  Radio,
  FileText,
  UserCheck,
  Zap,
  Globe,
  HelpCircle,
  Check,
  Server,
  Copy,
  Printer,
  LogOut,
  Key,
  UploadCloud,
  FileSpreadsheet,
  TrendingUp,
  Target,
  Layers,
  Filter,
  Eye,
  EyeOff,
  Sparkles
} from 'lucide-react';
import { RealCaptchaCanvas } from './RealCaptchaCanvas';
import { CicidsDatasetView } from './CicidsDatasetView';
import { ValidacionCicidsRealView } from './ValidacionCicidsRealView';
import { ReporteAcademicoView } from './ReporteAcademicoView';
import { CicidsEvaluationSummary } from './cicids_parser';
import { TrainingAndTestResult, TrainingConfig } from './ml_training_engine';

interface Intento {
  id: number;
  timestamp: number;
  ip: string;
  usuario: string;
  exitoso: boolean;
  es_ataque_real: number;
  alerta_reglas: number;
  alerta_ml: number;
  alerta_iforest: number;
  alerta_ocsvm: number;
  alerta_lof: number;
  score_ml: number;
  origen: string;
  es_simulado: number;
}

interface MetricaMetodo {
  verdaderos_positivos: number;
  falsos_negativos: number;
  falsos_positivos: number;
  verdaderos_negativos: number;
  precision: number;
  recall: number;
  f1: number;
  tasa_falsos_positivos?: number;
  especificidad?: number;
  accuracy?: number;
  latencia_ms_promedio?: number;
}

interface DesgloseVectorItem {
  total: number;
  detectado_reglas: number;
  detectado_ml: number;
  detectado_iforest: number;
  detectado_ocsvm: number;
  detectado_lof: number;
  pct_reglas: number;
  pct_ml: number;
  pct_iforest: number;
  pct_lof: number;
}

interface MetricasResumen {
  alerta_reglas: MetricaMetodo;
  alerta_iforest: MetricaMetodo;
  alerta_ocsvm: MetricaMetodo;
  alerta_lof: MetricaMetodo;
  alerta_ml: MetricaMetodo;
  total_intentos: number;
  desglose_vectores?: {
    rapido: DesgloseVectorItem;
    lento: DesgloseVectorItem;
    distribuido: DesgloseVectorItem;
    legitimo: DesgloseVectorItem;
  };
  rendimiento_computacional?: {
    latencia_promedio_total_ms: number;
    throughput_rps_estimado: number;
    memoria_heap_mb: number;
  };
}

interface EstadoModelo {
  fuente: string;
  detalle: string;
  cargando: boolean;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'simulator' | 'dataset_cicids' | 'cicids_real' | 'report' | 'demos' | 'training'>('dashboard');
  const [eventos, setEventos] = useState<Intento[]>([]);
  const [metricas, setMetricas] = useState<MetricasResumen | null>(null);
  const [ipsBloqueadas, setIpsBloqueadas] = useState<Record<string, number>>({});
  const [estadoModelo, setEstadoModelo] = useState<EstadoModelo>({ fuente: 'cicids2017', detalle: 'Cargando...', cargando: false });
  const [botLogs, setBotLogs] = useState<string[]>([]);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [matrizAlgoritmo, setMatrizAlgoritmo] = useState<'alerta_ml' | 'alerta_reglas' | 'alerta_iforest' | 'alerta_ocsvm' | 'alerta_lof'>('alerta_ml');

  // Estados del dataset CICIDS-2017 & Experimentos
  const [cicidsData, setCicidsData] = useState<CicidsEvaluationSummary | null>(null);
  const [cicidsCargando, setCicidsCargando] = useState(false);
  const [cicidsUmbral, setCicidsUmbral] = useState(0.55);
  const [resultadoEntrenamiento, setResultadoEntrenamiento] = useState<TrainingAndTestResult | null>(null);
  const [entrenandoMl, setEntrenandoMl] = useState(false);
  const [expBotnet, setExpBotnet] = useState<any>(null);
  const [expAblacion, setExpAblacion] = useState<any>(null);
  const [expTraficoReal, setExpTraficoReal] = useState<any>(null);

  // Bot simulator form state
  const [botTipo, setBotTipo] = useState<'rapido' | 'lento' | 'distribuido'>('rapido');
  const [botUsuario, setBotUsuario] = useState('admin');
  const [botIntentos, setBotIntentos] = useState(15);
  const [botIps, setBotIps] = useState(8);
  const [botIntervalo, setBotIntervalo] = useState(0.3);

  // Gate de autenticación con CAPTCHA para entrar a Centinela
  const [panelAutenticado, setPanelAutenticado] = useState<boolean>(() => {
    return localStorage.getItem('centinela_sesion_activa') === 'true';
  });
  const [gateUser, setGateUser] = useState('admin');
  const [gatePass, setGatePass] = useState('S3guro#2026');
  const [gateCaptchaId, setGateCaptchaId] = useState('');
  const [gateCaptchaInput, setGateCaptchaInput] = useState('');
  const [gateCaptchaReset, setGateCaptchaReset] = useState(0);
  const [gateError, setGateError] = useState<string | null>(null);
  const [gateCargando, setGateCargando] = useState(false);
  const [mostrarPassword, setMostrarPassword] = useState(false);

  // Demo login state
  const [demoMode, setDemoMode] = useState<'centinela' | 'vulnerable' | 'captcha' | '2fa'>('centinela');
  const [demoUser, setDemoUser] = useState('admin');
  const [demoPass, setDemoPass] = useState('');
  const [demoCaptchaInput, setDemoCaptchaInput] = useState('');
  const [demoCaptchaId, setDemoCaptchaId] = useState('');
  const [captchaResetCount, setCaptchaResetCount] = useState(0);
  const [demo2faStep, setDemo2faStep] = useState<1 | 2>(1);
  const [demo2faCode, setDemo2faCode] = useState('');
  const [demoResult, setDemoResult] = useState<{ status?: string; mensaje?: string; bloqueado?: boolean; score_ml?: number } | null>(null);

  const socketRef = useRef<any>(null);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 4000);
  };

  useEffect(() => {
    // Fetch initial data
    fetchData();

    // Socket.io connection
    const socket = io();
    socketRef.current = socket;

    socket.on('nuevo_evento', (evento: Intento) => {
      setEventos((prev) => [evento, ...prev].slice(0, 300));
      fetchMetricas();
      fetchBloqueadas();
    });

    socket.on('bot_log', (data: { mensaje: string }) => {
      setBotLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${data.mensaje}`]);
    });

    socket.on('entrenamiento_completo', (est: EstadoModelo) => {
      setEstadoModelo(est);
      showToast('Modelo re-entrenado exitosamente');
    });

    socket.on('entrenamiento_progreso', (data: { mensaje: string }) => {
      showToast(data.mensaje);
    });

    socket.on('reset', () => {
      setEventos([]);
      setMetricas(null);
      setIpsBloqueadas({});
      showToast('Sistema reiniciado');
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  const fetchData = async () => {
    try {
      const [resEv, resMet, resBloq, resMod] = await Promise.all([
        fetch('/api/eventos'),
        fetch('/api/metricas'),
        fetch('/api/bloqueadas'),
        fetch('/api/estado_modelo'),
      ]);
      if (resEv.ok) setEventos(await resEv.json());
      if (resMet.ok) setMetricas(await resMet.json());
      if (resBloq.ok) setIpsBloqueadas(await resBloq.json());
      if (resMod.ok) setEstadoModelo(await resMod.json());
    } catch (err) {
      console.error('Error fetching data:', err);
    }

    // Cargar datos de CICIDS y experimentos
    try {
      const [resCic, resExpBot, resExpAbl, resExpTraf, resTrain] = await Promise.all([
        fetch('/api/cicids/evaluacion'),
        fetch('/api/experimentos/botnet_distribuido'),
        fetch('/api/experimentos/ablacion'),
        fetch('/api/experimentos/trafico_real'),
        fetch('/api/cicids/resultado_entrenamiento'),
      ]);
      if (resCic.ok) {
        const cicJson = await resCic.json();
        setCicidsData(cicJson.evaluacion);
        if (cicJson.umbral) setCicidsUmbral(cicJson.umbral);
      }
      if (resExpBot.ok) setExpBotnet(await resExpBot.json());
      if (resExpAbl.ok) setExpAblacion(await resExpAbl.json());
      if (resExpTraf.ok) setExpTraficoReal(await resExpTraf.json());
      if (resTrain && resTrain.ok) {
        const trainJson = await resTrain.json();
        if (trainJson.resultado) setResultadoEntrenamiento(trainJson.resultado);
      }
    } catch (err) {
      console.error('Error fetching experiments:', err);
    }
  };

  const handleSubirArchivoCsv = async (file: File) => {
    setCicidsCargando(true);
    try {
      const formData = new FormData();
      formData.append('archivo', file);
      const res = await fetch('/api/cicids/cargar_csv', { method: 'POST', body: formData });
      const json = await res.json();
      if (res.ok) {
        setCicidsData(json.evaluacion);
        if (json.resultadoEntrenamiento) setResultadoEntrenamiento(json.resultadoEntrenamiento);
        if (json.umbral) setCicidsUmbral(json.umbral);
        showToast(`Dataset cargado: ${json.totalRegistros} flujos evaluados exitosamente`);
      } else {
        showToast(`Error: ${json.error}`);
      }
    } catch {
      showToast('Error al subir archivo CSV');
    } finally {
      setCicidsCargando(false);
    }
  };

  const handleCargarCsvTexto = async (texto: string) => {
    setCicidsCargando(true);
    try {
      const res = await fetch('/api/cicids/cargar_csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csvText: texto }),
      });
      const json = await res.json();
      if (res.ok) {
        setCicidsData(json.evaluacion);
        if (json.resultadoEntrenamiento) setResultadoEntrenamiento(json.resultadoEntrenamiento);
        if (json.umbral) setCicidsUmbral(json.umbral);
        showToast(`Dataset procesado: ${json.totalRegistros} flujos evaluados`);
      } else {
        showToast(`Error: ${json.error}`);
      }
    } catch {
      showToast('Error procesando CSV');
    } finally {
      setCicidsCargando(false);
    }
  };

  const handleCambiarUmbral = async (u: number) => {
    setCicidsUmbral(u);
    try {
      const res = await fetch('/api/cicids/evaluar_umbral', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ umbral: u }),
      });
      const json = await res.json();
      if (res.ok) {
        setCicidsData(json.evaluacion);
        if (json.resultadoEntrenamiento) setResultadoEntrenamiento(json.resultadoEntrenamiento);
      }
    } catch {}
  };

  const handleRestaurarCicids2500 = async () => {
    setCicidsCargando(true);
    try {
      const res = await fetch('/api/cicids/restaurar_muestra_2500', { method: 'POST' });
      const json = await res.json();
      if (res.ok) {
        setCicidsData(json.evaluacion);
        if (json.resultadoEntrenamiento) setResultadoEntrenamiento(json.resultadoEntrenamiento);
        if (json.umbral) setCicidsUmbral(json.umbral);
        showToast('Muestra de 2,500 registros CICIDS-2017 restaurada');
      }
    } catch {
      showToast('Error restaurando muestra');
    } finally {
      setCicidsCargando(false);
    }
  };

  const handleEntrenarConDataset = async () => {
    try {
      const res = await fetch('/api/cicids/entrenar_con_dataset', { method: 'POST' });
      const json = await res.json();
      if (res.ok) {
        showToast(`Centinela re-calibrado con flujos benignos de CICIDS2017`);
        fetchData();
      } else {
        showToast(`Error: ${json.error}`);
      }
    } catch {
      showToast('Error entrenando con dataset');
    }
  };

  const handleEjecutarEntrenamientoMl = async (configParams: Partial<TrainingConfig>) => {
    setEntrenandoMl(true);
    try {
      const res = await fetch('/api/cicids/entrenar_y_probar_ml', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configParams),
      });
      const json = await res.json();
      if (res.ok) {
        setResultadoEntrenamiento(json.resultado);
        if (json.estadoModelo) setEstadoModelo(json.estadoModelo);
        showToast('Modelos ML entrenados y probados exitosamente con CICIDS-2017');
      } else {
        showToast(json.error || 'Error entrenando modelos');
      }
    } catch {
      showToast('Error en pipeline de entrenamiento');
    } finally {
      setEntrenandoMl(false);
    }
  };

  const handleProbarFlujoEnVivo = async (params: Record<string, any>) => {
    const res = await fetch('/api/cicids/probar_flujo_en_vivo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Error en inferencia');
    return json;
  };

  const fetchMetricas = async () => {
    try {
      const res = await fetch('/api/metricas');
      if (res.ok) setMetricas(await res.json());
    } catch {}
  };

  const fetchBloqueadas = async () => {
    try {
      const res = await fetch('/api/bloqueadas');
      if (res.ok) setIpsBloqueadas(await res.json());
    } catch {}
  };

  const ejecutarSimulacion = async (tipo: string, extraBody = {}) => {
    setLoadingAction(tipo);
    try {
      const res = await fetch('/simular/ataque', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tipo, ...extraBody }),
      });
      const data = await res.json();
      showToast(`Ataque simulado (${tipo}) lanzado correctamente`);
    } catch (err) {
      showToast('Error al lanzar simulación');
    } finally {
      setLoadingAction(null);
    }
  };

  const ejecutarBenchmark = async () => {
    setLoadingAction('benchmark');
    try {
      const res = await fetch('/simular/benchmark_masivo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cantidad: 25000 }),
      });
      const data = await res.json();
      showToast(`Benchmark masivo de ${data.total_generados} eventos completado!`);
      fetchData();
    } catch (err) {
      showToast('Error ejecutando benchmark');
    } finally {
      setLoadingAction(null);
    }
  };

  const ejecutarLegitimo = async () => {
    setLoadingAction('legitimo');
    try {
      await fetch('/simular/legitimo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cantidad: 10 }),
      });
      showToast('Tráfico legítimo simulado');
    } catch {
      showToast('Error simulando tráfico legítimo');
    } finally {
      setLoadingAction(null);
    }
  };

  const reiniciarSistema = async () => {
    if (!confirm('¿Estás seguro de reiniciar todos los eventos, bloqueos y modelos de Centinela?')) return;
    try {
      await fetch('/reset', { method: 'POST' });
      fetchData();
      showToast('Sistema reiniciado con éxito');
    } catch {
      showToast('Error al reiniciar');
    }
  };

  const lanzarBotHttp = async () => {
    setLoadingAction('bot');
    try {
      const res = await fetch('/lanzar_bot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tipo: botTipo,
          usuario: botUsuario,
          intentos: botIntentos,
          ips: botIps,
          intervalo: botIntervalo,
          url: demoMode === 'vulnerable' ? '/demo/vulnerable/login' : demoMode === 'captcha' ? '/demo/captcha/login' : '/demo/login',
        }),
      });
      const data = await res.json();
      showToast(`Bot HTTP (${botTipo}) iniciado contra ${data.url}`);
    } catch {
      showToast('Error al lanzar bot HTTP');
    } finally {
      setLoadingAction(null);
    }
  };

  const reentrenarMl = async () => {
    setLoadingAction('reentrenar');
    try {
      const res = await fetch('/entrenar/reentrenar_con_trafico', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setEstadoModelo(data);
        showToast('Modelo re-entrenado con tráfico en vivo');
      } else {
        showToast(data.error || 'Error al reentrenar');
      }
    } catch {
      showToast('Error al reentrenar modelo');
    } finally {
      setLoadingAction(null);
    }
  };

  // Gate de autenticación con CAPTCHA para acceder a Centinela
  const handleGateLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setGateError(null);
    setGateCargando(true);
    try {
      const res = await fetch('/login-admin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          usuario: gateUser,
          password: gatePass,
          captcha: gateCaptchaInput,
          captchaId: gateCaptchaId,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        localStorage.setItem('centinela_sesion_activa', 'true');
        setPanelAutenticado(true);
        showToast('Acceso autorizado a Centinela');
      } else {
        setGateError(data.error || 'Fallo de autenticación');
        setGateCaptchaReset((prev) => prev + 1);
        setGateCaptchaInput('');
      }
    } catch (err: any) {
      setGateError(err.message || 'Error de conexión con el servidor');
      setGateCaptchaReset((prev) => prev + 1);
    } finally {
      setGateCargando(false);
    }
  };

  // Demo Login handlers
  const handleDemoLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setDemoResult(null);

    let endpoint = '/demo/login';
    let body: any = { usuario: demoUser, password: demoPass };

    if (demoMode === 'vulnerable') {
      endpoint = '/demo/vulnerable/login';
    } else if (demoMode === 'captcha') {
      endpoint = '/demo/captcha/login';
      body.captcha = demoCaptchaInput;
      body.captchaId = demoCaptchaId;
    } else if (demoMode === '2fa') {
      if (demo2faStep === 1) {
        endpoint = '/demo/2fa/login-paso1';
      } else {
        endpoint = '/demo/2fa/login-paso2';
        body = { usuario: demoUser, codigo: demo2faCode, codigoEsperado: '123456' };
      }
    }

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setDemoResult({ ...data, status: res.ok ? 'ok' : 'fallo' });
      if (demoMode === '2fa' && demo2faStep === 1 && res.ok) {
        setDemo2faStep(2);
      }
      if (demoMode === 'captcha') {
        setCaptchaResetCount((prev) => prev + 1);
        setDemoCaptchaInput('');
      }
    } catch (err: any) {
      setDemoResult({ status: 'fallo', mensaje: err.message || 'Error de conexión' });
      if (demoMode === 'captcha') {
        setCaptchaResetCount((prev) => prev + 1);
      }
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      {/* Toast Notification */}
      {toast && (
        <div className="fixed top-5 right-5 z-50 bg-cyan-600 text-white px-5 py-3 rounded-xl shadow-2xl border border-cyan-400 animate-bounce flex items-center space-x-3">
          <Zap className="w-5 h-5 text-yellow-300 animate-spin" />
          <span className="font-semibold">{toast}</span>
        </div>
      )}

      {!panelAutenticado ? (
        <div className="flex-1 flex items-center justify-center p-6 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950">
          <div className="max-w-md w-full bg-slate-900/95 border border-slate-800 rounded-3xl p-8 shadow-2xl relative overflow-hidden backdrop-blur-xl">
            {/* Ambient gradients */}
            <div className="absolute -top-20 -left-20 w-44 h-44 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
            <div className="absolute -bottom-20 -right-20 w-44 h-44 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

            <div className="flex flex-col items-center text-center mb-6">
              <div className="bg-gradient-to-tr from-cyan-600 to-blue-500 p-3.5 rounded-2xl shadow-xl shadow-cyan-500/25 mb-4">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <h2 className="text-2xl font-black tracking-wide bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                Acceso a Centinela
              </h2>
              <p className="text-xs text-slate-400 mt-1.5 max-w-xs leading-relaxed">
                Panel de control de ciberseguridad protegido con <strong className="text-cyan-300">desafío CAPTCHA real</strong> en servidor
              </p>
            </div>

            {gateError && (
              <div className="mb-5 bg-red-500/10 border border-red-500/30 text-red-400 text-xs px-4 py-3 rounded-xl flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                <span>{gateError}</span>
              </div>
            )}

            <form onSubmit={handleGateLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase mb-1.5">Usuario de Administrador</label>
                <input
                  type="text"
                  value={gateUser}
                  onChange={(e) => setGateUser(e.target.value)}
                  placeholder="admin"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-bold text-slate-300 uppercase">Contraseña de Administrador</label>
                  <button
                    type="button"
                    onClick={() => setMostrarPassword(!mostrarPassword)}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                  >
                    {mostrarPassword ? (
                      <>
                        <EyeOff className="w-3.5 h-3.5" />
                        <span>Ocultar</span>
                      </>
                    ) : (
                      <>
                        <Eye className="w-3.5 h-3.5" />
                        <span>Mostrar</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="relative">
                  <input
                    type={mostrarPassword ? 'text' : 'password'}
                    value={gatePass}
                    onChange={(e) => setGatePass(e.target.value)}
                    placeholder="S3guro#2026"
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
                  />
                </div>
              </div>

              {/* Botón rápido para autocompletar credenciales por defecto */}
              <div className="flex items-center justify-between text-[11px] bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                <span className="text-slate-400">Credenciales por defecto:</span>
                <button
                  type="button"
                  onClick={() => {
                    setGateUser('admin');
                    setGatePass('S3guro#2026');
                    showToast('Credenciales admin / S3guro#2026 aplicadas');
                  }}
                  className="text-cyan-400 hover:text-cyan-300 font-bold flex items-center space-x-1 cursor-pointer bg-cyan-950/60 hover:bg-cyan-900/60 px-2.5 py-1 rounded-lg border border-cyan-800/60 transition-colors"
                >
                  <Sparkles className="w-3 h-3 text-yellow-300" />
                  <span>Autocompletar (admin / S3guro#2026)</span>
                </button>
              </div>

              <div className="bg-slate-950/80 p-4 rounded-2xl border border-slate-800/90 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-300 flex items-center space-x-1.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Desafío Anti-Bot CAPTCHA:</span>
                  </span>
                  <span className="text-[10px] text-cyan-400 font-medium bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/60">
                    Criptográfico / Anti-Replay
                  </span>
                </div>

                <RealCaptchaCanvas
                  onCaptchaReady={(id) => setGateCaptchaId(id)}
                  resetTrigger={gateCaptchaReset}
                />

                <input
                  type="text"
                  placeholder="Ingresa el código CAPTCHA visual"
                  value={gateCaptchaInput}
                  onChange={(e) => setGateCaptchaInput(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 uppercase tracking-widest font-mono text-center font-bold"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={gateCargando || !gateCaptchaId}
                className="w-full py-3.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded-xl shadow-lg shadow-cyan-600/30 transition-all flex items-center justify-center space-x-2 text-sm disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {gateCargando ? (
                  <>
                    <Zap className="w-4 h-4 animate-spin text-yellow-300" />
                    <span>Verificando CAPTCHA y credenciales...</span>
                  </>
                ) : (
                  <>
                    <Key className="w-4 h-4" />
                    <span>Verificar Desafío y Acceder al Panel</span>
                  </>
                )}
              </button>
            </form>

            <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-col items-center space-y-2">
              <button
                type="button"
                onClick={() => {
                  localStorage.setItem('centinela_sesion_activa', 'true');
                  setPanelAutenticado(true);
                  showToast('Acceso directo al panel activado');
                }}
                className="text-xs text-slate-400 hover:text-cyan-300 underline transition-colors cursor-pointer"
              >
                ¿Deseas omitir el inicio de sesión y entrar directamente al panel? Haz clic aquí
              </button>
              <p className="text-[10px] text-slate-500 text-center">
                El servidor consume y destruye el token de CAPTCHA al validarlo para prevenir ataques por fuerza bruta.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <>
          {/* Header */}
          <header className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4 shadow-lg sticky top-0 z-40">
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-tr from-cyan-600 to-blue-500 p-2.5 rounded-2xl shadow-lg shadow-cyan-500/20">
                <Shield className="w-7 h-7 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-black tracking-wider bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                  CENTINELA
                </h1>
                <p className="text-xs text-slate-400 font-medium">Adaptive Brute Force Detector & WAF / ML Mitigation</p>
              </div>
            </div>

            {/* Navigation Tabs */}
            <nav className="flex items-center bg-slate-950/80 p-1.5 rounded-2xl border border-slate-800 space-x-1">
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all ${
                  activeTab === 'dashboard'
                    ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Activity className="w-4 h-4" />
                <span>Dashboard</span>
              </button>
              <button
                onClick={() => setActiveTab('simulator')}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
                  activeTab === 'simulator'
                    ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Play className="w-4 h-4" />
                <span>Simulador & Bot</span>
              </button>
              <button
                onClick={() => setActiveTab('dataset_cicids')}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
                  activeTab === 'dataset_cicids'
                    ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Database className="w-4 h-4 text-emerald-400" />
                <span>Dataset CICIDS-2017</span>
                {cicidsData && (
                  <span className="bg-emerald-500/20 text-emerald-300 text-[10px] px-1.5 py-0.5 rounded-full font-bold">
                    {cicidsData.totalRegistros}
                  </span>
                )}
              </button>
              <button
                onClick={() => setActiveTab('cicids_real')}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
                  activeTab === 'cicids_real'
                    ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/30'
                    : 'text-emerald-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Shield className="w-4 h-4 text-emerald-400" />
                <span>Validación CICIDS2017 (datos reales)</span>
                <span className="bg-emerald-500/25 text-emerald-300 text-[9px] px-1.5 py-0.5 rounded-md font-black uppercase tracking-wider border border-emerald-400/30">
                  REAL
                </span>
              </button>
              <button
                onClick={() => setActiveTab('report')}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
                  activeTab === 'report'
                    ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <BarChart2 className="w-4 h-4" />
                <span>Reporte Científico</span>
              </button>
              <button
                onClick={() => setActiveTab('demos')}
                className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all ${
                  activeTab === 'demos'
                    ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Lock className="w-4 h-4" />
                <span>Logins Demo</span>
              </button>
              <button
                onClick={() => setActiveTab('training')}
                className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all ${
                  activeTab === 'training'
                    ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Cpu className="w-4 h-4" />
                <span>ML & Entrenamiento</span>
              </button>
            </nav>

            {/* Status / Quick Reset / Logout */}
            <div className="flex items-center space-x-3">
              <div className="hidden lg:flex items-center space-x-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-3 py-1.5 rounded-full text-xs font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                <span>WAF & ML Activos</span>
              </div>
              <button
                onClick={reiniciarSistema}
                title="Reiniciar sistema"
                className="p-2.5 bg-slate-800 hover:bg-red-600/20 hover:border-red-500/50 text-slate-300 hover:text-red-400 border border-slate-700 rounded-xl transition-all cursor-pointer"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
              <button
                onClick={() => {
                  localStorage.removeItem('centinela_sesion_activa');
                  setPanelAutenticado(false);
                  setGateCaptchaReset((prev) => prev + 1);
                  setGateCaptchaInput('');
                  fetch('/logout-admin', { method: 'POST' }).catch(() => {});
                  showToast('Sesión de Centinela cerrada');
                }}
                title="Cerrar sesión"
                className="flex items-center space-x-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-rose-400 border border-slate-700 rounded-xl transition-all text-xs font-semibold cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Cerrar Sesión</span>
              </button>
            </div>
          </header>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {activeTab === 'dashboard' && (
          <div className="space-y-6 animate-fadeIn">
            {/* Top Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl shadow-xl relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <p className="text-xs uppercase tracking-wider text-slate-400 font-bold">Total Eventos</p>
                    <h3 className="text-3xl font-extrabold text-white mt-1">{metricas?.total_intentos || eventos.length}</h3>
                  </div>
                  <div className="bg-blue-500/10 p-3 rounded-xl border border-blue-500/20 text-blue-400">
                    <Activity className="w-6 h-6" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-xs text-slate-400 space-x-1">
                  <span className="text-emerald-400 font-semibold">En tiempo real</span>
                  <span>vía Socket.io</span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl shadow-xl relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <p className="text-xs uppercase tracking-wider text-slate-400 font-bold">IPs Bloqueadas</p>
                    <h3 className="text-3xl font-extrabold text-red-400 mt-1">{Object.keys(ipsBloqueadas).length}</h3>
                  </div>
                  <div className="bg-red-500/10 p-3 rounded-xl border border-red-500/20 text-red-400">
                    <Shield className="w-6 h-6" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-xs text-slate-400 space-x-1">
                  <span className="text-red-400 font-semibold">Mitigación activa</span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl shadow-xl relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <p className="text-xs uppercase tracking-wider text-slate-400 font-bold">Ensamble ML F1</p>
                    <h3 className="text-3xl font-extrabold text-cyan-400 mt-1">
                      {metricas ? `${(metricas.alerta_ml.f1 * 100).toFixed(1)}%` : '—'}
                    </h3>
                  </div>
                  <div className="bg-cyan-500/10 p-3 rounded-xl border border-cyan-500/20 text-cyan-400">
                    <Cpu className="w-6 h-6" />
                  </div>
                </div>
                <div className="mt-4 flex items-center text-xs text-slate-400 space-x-1">
                  <span className="text-cyan-400 font-semibold">IsolationForest + OC-SVM + LOF</span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl shadow-xl relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <p className="text-xs uppercase tracking-wider text-slate-400 font-bold">Modelo Activo</p>
                    <h3 className="text-lg font-bold text-white mt-1 truncate max-w-[180px]">
                      {estadoModelo.fuente.toUpperCase()}
                    </h3>
                  </div>
                  <div className="bg-purple-500/10 p-3 rounded-xl border border-purple-500/20 text-purple-400">
                    <Database className="w-6 h-6" />
                  </div>
                </div>
                <div className="mt-2 text-xs text-slate-400 truncate">
                  {estadoModelo.detalle}
                </div>
              </div>
            </div>

            {/* Quick Actions & Simulation Bar */}
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl shadow-xl flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center space-x-3">
                <Zap className="w-5 h-5 text-cyan-400" />
                <h2 className="text-base font-bold text-white">Centro de Control de Pruebas y Simuladores</h2>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <button
                  disabled={loadingAction !== null}
                  onClick={() => ejecutarSimulacion('rapido')}
                  className="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 rounded-xl text-xs font-bold transition-all flex items-center space-x-2"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Simular Ataque Rápido</span>
                </button>
                <button
                  disabled={loadingAction !== null}
                  onClick={() => ejecutarSimulacion('lento')}
                  className="px-4 py-2 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 rounded-xl text-xs font-bold transition-all flex items-center space-x-2"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Simular Ataque Lento</span>
                </button>
                <button
                  disabled={loadingAction !== null}
                  onClick={() => ejecutarSimulacion('distribuido')}
                  className="px-4 py-2 bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 border border-purple-500/30 rounded-xl text-xs font-bold transition-all flex items-center space-x-2"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Simular Distribuido (Botnet)</span>
                </button>
                <button
                  disabled={loadingAction !== null}
                  onClick={ejecutarLegitimo}
                  className="px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-xl text-xs font-bold transition-all flex items-center space-x-2"
                >
                  <UserCheck className="w-3.5 h-3.5" />
                  <span>Generar Tráfico Legítimo</span>
                </button>
                <button
                  disabled={loadingAction !== null}
                  onClick={ejecutarBenchmark}
                  className="px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-600/20 rounded-xl text-xs font-bold transition-all flex items-center space-x-2"
                >
                  <Zap className="w-3.5 h-3.5 text-yellow-300" />
                  <span>Ejecutar Benchmark Masivo (25k)</span>
                </button>
              </div>
            </div>

            {/* Main Grid: Event Stream & Blocked IPs */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Event Stream Table (2 columns) */}
              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden flex flex-col">
                <div className="p-5 border-b border-slate-800 flex justify-between items-center bg-slate-950/40">
                  <div className="flex items-center space-x-2">
                    <Terminal className="w-5 h-5 text-cyan-400" />
                    <h3 className="font-bold text-white">Stream de Eventos en Tiempo Real</h3>
                  </div>
                  <span className="text-xs bg-slate-800 text-slate-300 px-3 py-1 rounded-full font-medium">
                    {eventos.length} eventos registrados
                  </span>
                </div>
                <div className="overflow-x-auto max-h-[550px] overflow-y-auto">
                  <table className="w-full text-left border-collapse">
                    <thead className="bg-slate-950/80 sticky top-0 text-xs text-slate-400 uppercase tracking-wider border-b border-slate-800">
                      <tr>
                        <th className="p-3.5">Timestamp</th>
                        <th className="p-3.5">IP Origen</th>
                        <th className="p-3.5">Usuario</th>
                        <th className="p-3.5">Estado</th>
                        <th className="p-3.5">Detección WAF / ML</th>
                        <th className="p-3.5">Score ML</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-sm">
                      {eventos.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="p-8 text-center text-slate-500">
                            No hay eventos registrados aún. Usa los simuladores o realiza pruebas de login.
                          </td>
                        </tr>
                      ) : (
                        eventos.map((ev) => (
                          <tr key={ev.id} className="hover:bg-slate-800/40 transition-colors">
                            <td className="p-3.5 font-mono text-xs text-slate-400">
                              {new Date(ev.timestamp * 1000).toLocaleTimeString()}
                            </td>
                            <td className="p-3.5 font-mono text-xs text-cyan-300">{ev.ip}</td>
                            <td className="p-3.5 font-medium text-slate-200">{ev.usuario}</td>
                            <td className="p-3.5">
                              {ev.exitoso ? (
                                <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                  <CheckCircle2 className="w-3 h-3" />
                                  <span>Exitoso</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-500/10 text-red-400 border border-red-500/20">
                                  <XCircle className="w-3 h-3" />
                                  <span>Fallido</span>
                                </span>
                              )}
                            </td>
                            <td className="p-3.5">
                              <div className="flex flex-wrap gap-1">
                                {ev.alerta_reglas === 1 && (
                                  <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-bold">
                                    WAF Reglas
                                  </span>
                                )}
                                {ev.alerta_ml === 1 && (
                                  <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 text-[10px] font-bold">
                                    Ensamble ML
                                  </span>
                                )}
                                {ev.alerta_reglas === 0 && ev.alerta_ml === 0 && (
                                  <span className="text-xs text-slate-500">Normal</span>
                                )}
                              </div>
                            </td>
                            <td className="p-3.5 font-mono text-xs">
                              <span
                                className={`font-bold ${
                                  ev.score_ml > 0.7 ? 'text-red-400' : ev.score_ml > 0.4 ? 'text-amber-400' : 'text-emerald-400'
                                }`}
                              >
                                {ev.score_ml.toFixed(3)}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Blocked IPs Panel (1 column) */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden flex flex-col">
                <div className="p-5 border-b border-slate-800 bg-slate-950/40 flex justify-between items-center">
                  <div className="flex items-center space-x-2">
                    <Shield className="w-5 h-5 text-red-400" />
                    <h3 className="font-bold text-white">IPs Bloqueadas WAF</h3>
                  </div>
                  <span className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2.5 py-0.5 rounded-full font-bold">
                    {Object.keys(ipsBloqueadas).length}
                  </span>
                </div>
                <div className="p-5 flex-1 overflow-y-auto space-y-3 max-h-[500px]">
                  {Object.keys(ipsBloqueadas).length === 0 ? (
                    <div className="text-center py-12 text-slate-500 text-sm">
                      No hay direcciones IP bloqueadas actualmente. El sistema está vigilando.
                    </div>
                  ) : (
                    Object.entries(ipsBloqueadas).map(([ip, segundos]) => (
                      <div key={ip} className="bg-slate-950/60 border border-red-500/20 p-4 rounded-xl flex items-center justify-between">
                        <div>
                          <p className="font-mono text-sm font-bold text-red-400">{ip}</p>
                          <p className="text-xs text-slate-400 mt-0.5">Expira en {segundos}s</p>
                        </div>
                        <button
                          onClick={async () => {
                            await fetch('/reset', { method: 'POST' }); // or specific unblock if implemented
                            fetchBloqueadas();
                          }}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-all"
                        >
                          Liberar
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'simulator' && (
          <div className="space-y-6 animate-fadeIn">
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl">
              <div className="flex items-center space-x-3 mb-6">
                <div className="bg-cyan-500/10 p-3 rounded-xl border border-cyan-500/20 text-cyan-400">
                  <Play className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white">Simulador de Bot Atacante y Pruebas de Estrés</h2>
                  <p className="text-xs text-slate-400">Lanza ataques simulados en tiempo real y observa las respuestas del WAF y los modelos de Machine Learning.</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Tipo de Ataque</label>
                    <select
                      value={botTipo}
                      onChange={(e) => setBotTipo(e.target.value as any)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="rapido">Ataque Rápido (Ráfaga Clásica)</option>
                      <option value="lento">Ataque Lento (Low-and-Slow Sigiloso)</option>
                      <option value="distribuido">Ataque Distribuido (Botnet Multi-IP)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Usuario Objetivo</label>
                    <input
                      type="text"
                      value={botUsuario}
                      onChange={(e) => setBotUsuario(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Cantidad de Intentos</label>
                    <input
                      type="number"
                      value={botIntentos}
                      onChange={(e) => setBotIntentos(parseInt(e.target.value) || 10)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <button
                    onClick={lanzarBotHttp}
                    disabled={loadingAction !== null}
                    className="w-full py-3.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded-xl shadow-lg shadow-cyan-600/30 transition-all flex items-center justify-center space-x-2"
                  >
                    <Play className="w-4 h-4 text-yellow-300" />
                    <span>Lanzar Bot Atacante</span>
                  </button>
                </div>

                {/* Terminal / Logs (2 columns) */}
                <div className="md:col-span-2 bg-slate-950 border border-slate-800 rounded-2xl p-5 flex flex-col h-[400px]">
                  <div className="flex justify-between items-center pb-3 border-b border-slate-800 mb-3">
                    <div className="flex items-center space-x-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Terminal de Logs del Bot</span>
                    </div>
                    <button
                      onClick={() => setBotLogs([])}
                      className="text-xs text-slate-400 hover:text-white px-2.5 py-1 bg-slate-900 hover:bg-slate-800 rounded-lg transition-all"
                    >
                      Limpiar
                    </button>
                  </div>
                  <div className="flex-1 overflow-y-auto font-mono text-xs space-y-1.5 text-cyan-300/90">
                    {botLogs.length === 0 ? (
                      <span className="text-slate-600">Esperando ejecución de ataques... Los logs en tiempo real aparecerán aquí.</span>
                    ) : (
                      botLogs.map((log, idx) => (
                        <div key={idx} className="leading-relaxed">
                          {log}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'dataset_cicids' && (
          <CicidsDatasetView
            data={cicidsData}
            resultadoEntrenamiento={resultadoEntrenamiento}
            cargando={cicidsCargando}
            entrenandoMl={entrenandoMl}
            umbral={cicidsUmbral}
            onCambiarUmbral={handleCambiarUmbral}
            onCargarArchivo={handleSubirArchivoCsv}
            onCargarCsvTexto={handleCargarCsvTexto}
            onRestaurarMuestra2500={handleRestaurarCicids2500}
            onEntrenarConDataset={handleEntrenarConDataset}
            onEjecutarEntrenamientoMl={handleEjecutarEntrenamientoMl}
            onProbarFlujoEnVivo={handleProbarFlujoEnVivo}
            showToast={showToast}
          />
        )}

        {activeTab === 'cicids_real' && (
          <ValidacionCicidsRealView showToast={showToast} />
        )}

        {activeTab === 'report' && (
          <ReporteAcademicoView
            metricas={metricas}
            estadoModelo={estadoModelo}
            expBotnet={expBotnet}
            expAblacion={expAblacion}
            expTraficoReal={expTraficoReal}
            cicidsData={cicidsData}
            umbral={cicidsUmbral}
            onCambiarUmbral={handleCambiarUmbral}
            showToast={showToast}
          />
        )}

        {activeTab === 'demos' && (
          <div className="space-y-6 animate-fadeIn">
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl">
              <h2 className="text-lg font-bold text-white mb-2">Demostración de Niveles de Seguridad</h2>
              <p className="text-xs text-slate-400 mb-6">Prueba diferentes configuraciones de autenticación para ver cómo Centinela defiende aplicaciones frente a ataques de fuerza bruta.</p>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                <button
                  onClick={() => setDemoMode('centinela')}
                  className={`p-4 rounded-xl border text-left font-semibold text-sm transition-all ${
                    demoMode === 'centinela' ? 'bg-cyan-600/20 border-cyan-500 text-cyan-300 shadow-lg' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Shield className="w-5 h-5 mb-2 text-cyan-400" />
                  <div>Centinela (Protegido)</div>
                </button>
                <button
                  onClick={() => setDemoMode('vulnerable')}
                  className={`p-4 rounded-xl border text-left font-semibold text-sm transition-all ${
                    demoMode === 'vulnerable' ? 'bg-red-600/20 border-red-500 text-red-300 shadow-lg' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <AlertTriangle className="w-5 h-5 mb-2 text-red-400" />
                  <div>Login Vulnerable</div>
                </button>
                <button
                  onClick={() => setDemoMode('captcha')}
                  className={`p-4 rounded-xl border text-left font-semibold text-sm transition-all ${
                    demoMode === 'captcha' ? 'bg-amber-600/20 border-amber-500 text-amber-300 shadow-lg' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Lock className="w-5 h-5 mb-2 text-amber-400" />
                  <div>Login CAPTCHA</div>
                </button>
                <button
                  onClick={() => setDemoMode('2fa')}
                  className={`p-4 rounded-xl border text-left font-semibold text-sm transition-all ${
                    demoMode === '2fa' ? 'bg-purple-600/20 border-purple-500 text-purple-300 shadow-lg' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Zap className="w-5 h-5 mb-2 text-purple-400" />
                  <div>Login 2FA / TOTP</div>
                </button>
              </div>

              {/* Login Form Container */}
              <div className="max-w-md mx-auto bg-slate-950 border border-slate-800 p-6 rounded-2xl shadow-xl">
                <h3 className="text-base font-bold text-white mb-4 uppercase tracking-wider text-center">
                  {demoMode === 'centinela' && 'Acceso Seguro — Centinela'}
                  {demoMode === 'vulnerable' && 'Acceso Vulnerable (Sin WAF)'}
                  {demoMode === 'captcha' && 'Desafío Anti-Bot CAPTCHA'}
                  {demoMode === '2fa' && 'Autenticación de Dos Factores (2FA)'}
                </h3>

                <form onSubmit={handleDemoLogin} className="space-y-4">
                  {demoMode !== '2fa' || demo2faStep === 1 ? (
                    <>
                      <div>
                        <label className="block text-xs font-bold text-slate-300 uppercase mb-1">Usuario (ej. admin, jperez)</label>
                        <input
                          type="text"
                          value={demoUser}
                          onChange={(e) => setDemoUser(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-bold text-slate-300 uppercase mb-1">Contraseña</label>
                        <input
                          type="password"
                          value={demoPass}
                          onChange={(e) => setDemoPass(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                          required
                        />
                      </div>
                    </>
                  ) : null}

                  {demoMode === 'captcha' && (
                    <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 space-y-3">
                      <label className="text-xs text-slate-400 font-bold block">Desafío CAPTCHA Visual (Criptográfico en Servidor):</label>
                      <RealCaptchaCanvas
                        onCaptchaReady={(id) => setDemoCaptchaId(id)}
                        resetTrigger={captchaResetCount}
                      />
                      <input
                        type="text"
                        placeholder="Ingresa el código CAPTCHA visual"
                        value={demoCaptchaInput}
                        onChange={(e) => setDemoCaptchaInput(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 uppercase tracking-widest font-mono"
                        required
                      />
                    </div>
                  )}

                  {demoMode === '2fa' && demo2faStep === 2 && (
                    <div className="space-y-3">
                      <p className="text-xs text-slate-400">Introduce el código de 6 dígitos enviado a tu dispositivo (puedes usar <strong className="text-cyan-400">123456</strong>):</p>
                      <input
                        type="text"
                        maxLength={6}
                        placeholder="123456"
                        value={demo2faCode}
                        onChange={(e) => setDemo2faCode(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-center text-lg font-mono tracking-widest text-slate-200 focus:outline-none focus:border-cyan-500"
                        required
                      />
                    </div>
                  )}

                  <button
                    type="submit"
                    className="w-full py-3.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl shadow-lg shadow-cyan-600/30 transition-all"
                  >
                    {demoMode === '2fa' && demo2faStep === 2 ? 'Verificar Código 2FA' : 'Iniciar Sesión'}
                  </button>
                </form>

                {demoResult && (
                  <div
                    className={`mt-4 p-4 rounded-xl text-xs font-semibold border ${
                      demoResult.status === 'ok'
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                        : 'bg-red-500/10 border-red-500/30 text-red-400'
                    }`}
                  >
                    <p className="font-bold">{demoResult.mensaje || (demoResult.status === 'ok' ? 'Acceso concedido' : 'Acceso denegado')}</p>
                    {demoResult.score_ml !== undefined && (
                      <p className="mt-1 font-mono">Score Anomaly ML: {demoResult.score_ml.toFixed(3)}</p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'training' && (
          <div className="space-y-6 animate-fadeIn">
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-6">
              <div className="flex items-center space-x-3">
                <div className="bg-purple-500/10 p-3 rounded-xl border border-purple-500/20 text-purple-400">
                  <Cpu className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white">Configuración y Entrenamiento de Machine Learning</h2>
                  <p className="text-xs text-slate-400">Gestiona los modelos de detección de anomalías (Isolation Forest, One-Class SVM, Local Outlier Factor).</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl space-y-4">
                  <h3 className="font-bold text-white text-sm">Estado Actual del Modelo</h3>
                  <div className="space-y-2 text-xs text-slate-300">
                    <p><strong className="text-cyan-400">Fuente:</strong> {estadoModelo.fuente}</p>
                    <p><strong className="text-cyan-400">Detalle:</strong> {estadoModelo.detalle}</p>
                  </div>
                  <button
                    onClick={reentrenarMl}
                    disabled={loadingAction !== null}
                    className="w-full py-3 bg-purple-600 hover:bg-purple-500 text-white font-bold rounded-xl shadow-lg shadow-purple-600/30 transition-all text-xs"
                  >
                    Re-entrenar con Tráfico en Vivo Capturado
                  </button>
                </div>

                <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl space-y-4">
                  <h3 className="font-bold text-white text-sm">Generador CICIDS2017 Sintético</h3>
                  <p className="text-xs text-slate-400">Reinicia y entrena los detectores con 50,000 flujos benignos de alta resolución basados en CICIDS2017.</p>
                  <button
                    onClick={async () => {
                      await fetch('/entrenar/reset_sintetico', { method: 'POST' });
                      fetchData();
                      showToast('Modelos reiniciados con CICIDS2017');
                    }}
                    className="w-full py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded-xl border border-slate-700 transition-all text-xs"
                  >
                    Restaurar Dataset CICIDS2017 (50k)
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
      </>
      )}
    </div>
  );
}
