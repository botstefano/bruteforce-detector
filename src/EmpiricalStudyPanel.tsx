import React, { useCallback, useEffect, useMemo, useState } from 'react';

type GroundTruth = 'unknown' | 'benign' | 'attack';
type DatasetSplit = 'unassigned' | 'train' | 'validation' | 'test';

interface CapturedEvent {
  event_id: string;
  occurred_at: string;
  source_ip_hash: string;
  user_key_hash: string;
  auth_success: boolean;
  origin: string;
  ground_truth_label: GroundTruth;
  ground_truth_method: string | null;
  ground_truth_notes: string | null;
  dataset_split: DatasetSplit;
  alerta_reglas: boolean;
  alerta_ml: boolean;
  score_ml: number;
  latency_total_ms: number;
  campaign_id: string | null;
}

interface ActiveExperiment {
  id: string;
  trainEndMs: number;
  validationEndMs: number;
  trainingFrozen: boolean;
}

interface HealthSnapshot {
  status?: string;
  db_ok?: boolean;
  supabase_ok?: boolean;
  event_store?: { configured?: boolean; clientConfigured?: boolean; hashSecretConfigured?: boolean };
  capture_paused?: boolean;
  capture_pause_reason?: string | null;
  active_experiment?: boolean;
  active_experiment_boundaries_valid?: boolean;
  capture_ready?: boolean;
  backend_integration_ready?: boolean;
  ingest_token_configured?: boolean;
}

interface ExperimentSnapshot {
  active_experiment: ActiveExperiment | null;
  capture_paused: boolean;
  capture_pause_reason: string | null;
}

interface LabelDraft {
  method: string;
  rationale: string;
}

async function readJson(response: Response): Promise<any> {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `La solicitud falló (HTTP ${response.status}).`);
  }
  return payload;
}

function formatDate(value: string | number): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function formatNumber(value: number | null | undefined, digits = 2): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : '—';
}

export function EmpiricalStudyPanel() {
  const [health, setHealth] = useState<HealthSnapshot | null>(null);
  const [experiment, setExperiment] = useState<ActiveExperiment | null>(null);
  const [events, setEvents] = useState<CapturedEvent[]>([]);
  const [eventPage, setEventPage] = useState(1);
  const [protocolName, setProtocolName] = useState('centinela-auth-study-v1');
  const [scenario, setScenario] = useState('authorized-authentication-testbed');
  const [description, setDescription] = useState('Captura preregistrada de solicitudes reales de autenticación observadas por Centinela.');
  const [trainEndAt, setTrainEndAt] = useState('');
  const [validationEndAt, setValidationEndAt] = useState('');
  const [drafts, setDrafts] = useState<Record<string, LabelDraft>>({});
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [healthResponse, stateResponse] = await Promise.all([
        fetch('/health', { credentials: 'same-origin', cache: 'no-store' }),
        fetch('/api/experimentos/estado', { credentials: 'same-origin', cache: 'no-store' }),
      ]);
      const [healthJson, stateJson] = await Promise.all([
        readJson(healthResponse),
        readJson(stateResponse),
      ]);
      setHealth(healthJson);
      const current = (stateJson.active_experiment ?? null) as ActiveExperiment | null;
      setExperiment(current);
      if (current) {
        const eventsResponse = await fetch(
          `/api/dataset/capturado?experiment_id=${encodeURIComponent(current.id)}`,
          { credentials: 'same-origin', cache: 'no-store' }
        );
        const eventsJson = await readJson(eventsResponse);
        setEvents(Array.isArray(eventsJson.events) ? eventsJson.events : []);
      } else {
        setEvents([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo cargar el estado experimental.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const counts = useMemo(() => {
    const result = {
      total: events.length,
      train: 0,
      validation: 0,
      test: 0,
      unknown: 0,
      benign: 0,
      attack: 0,
    };
    for (const event of events) {
      if (event.dataset_split === 'train') result.train++;
      if (event.dataset_split === 'validation') result.validation++;
      if (event.dataset_split === 'test') result.test++;
      if (event.ground_truth_label === 'unknown') result.unknown++;
      if (event.ground_truth_label === 'benign') result.benign++;
      if (event.ground_truth_label === 'attack') result.attack++;
    }
    return result;
  }, [events]);

  const EVENTS_PER_PAGE = 20;
  const sortedEvents = useMemo(
    () => [...events].sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at)),
    [events]
  );
  const totalEventPages = Math.max(1, Math.ceil(sortedEvents.length / EVENTS_PER_PAGE));
  const firstVisibleEvent = sortedEvents.length === 0 ? 0 : (eventPage - 1) * EVENTS_PER_PAGE + 1;
  const lastVisibleEvent = Math.min(eventPage * EVENTS_PER_PAGE, sortedEvents.length);
  const paginatedEvents = useMemo(
    () => sortedEvents.slice((eventPage - 1) * EVENTS_PER_PAGE, eventPage * EVENTS_PER_PAGE),
    [sortedEvents, eventPage]
  );

  const sendAction = async (name: string, url: string, body?: Record<string, unknown>) => {
    setAction(name);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const payload = await readJson(response);
      setNotice(payload.message || payload.mensaje || 'Operación completada.');
      await load();
      return payload;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'La operación no pudo completarse.');
      return null;
    } finally {
      setAction(null);
    }
  };

  const createExperiment = async (event: React.FormEvent) => {
    event.preventDefault();
    const trainMs = new Date(trainEndAt).getTime();
    const validationMs = new Date(validationEndAt).getTime();
    if (!Number.isFinite(trainMs) || !Number.isFinite(validationMs)) {
      setError('Indica las dos fechas de corte.');
      return;
    }
    if (trainMs <= Date.now() || validationMs <= trainMs) {
      setError('El fin de entrenamiento debe ser futuro y el fin de validación debe ser posterior.');
      return;
    }
    await sendAction('create', '/api/experimentos', {
      protocol_name: protocolName,
      scenario,
      description,
      train_end_at: new Date(trainMs).toISOString(),
      validation_end_at: new Date(validationMs).toISOString(),
    });
  };

  const labelEvent = async (item: CapturedEvent, label: Exclude<GroundTruth, 'unknown'>) => {
    const draft = drafts[item.event_id];
    if (!draft?.method.trim() || !draft?.rationale.trim()) {
      setError('Para etiquetar un evento debes indicar el método de verificación y la evidencia que justifica la etiqueta.');
      return;
    }
    const result = await sendAction(
      `label-${item.event_id}`,
      `/api/eventos/${encodeURIComponent(item.event_id)}/etiqueta`,
      { label, method: draft.method.trim(), rationale: draft.rationale.trim() }
    );
    if (result) {
      setDrafts((previous) => {
        const next = { ...previous };
        delete next[item.event_id];
        return next;
      });
    }
  };

  const trainModel = async () => {
    await sendAction('train', '/api/experimentos/entrenar_con_eventos_capturados');
  };

  const finishExperiment = async () => {
    if (!experiment) return;
    if (!window.confirm('¿Finalizar el experimento? La captura quedará cerrada para este identificador.')) return;
    await sendAction('finish', `/api/experimentos/${encodeURIComponent(experiment.id)}/finalizar`);
  };

  const abortExperiment = async () => {
    if (!experiment) return;
    const reason = window.prompt('Describe por qué debe abortarse esta ejecución. La razón quedará registrada en Supabase:');
    if (!reason?.trim()) return;
    await sendAction('abort', `/api/experimentos/${encodeURIComponent(experiment.id)}/abortar`, { reason: reason.trim() });
  };

  const updateDraft = (eventId: string, field: keyof LabelDraft, value: string) => {
    setDrafts((previous) => ({
      ...previous,
      [eventId]: {
        method: previous[eventId]?.method ?? '',
        rationale: previous[eventId]?.rationale ?? '',
        [field]: value,
      },
    }));
  };

  const captureReady = health?.capture_ready === true;
  const statusText = loading ? 'Consultando estado…'
    : health?.supabase_ok ? 'Supabase accesible'
    : health?.event_store?.configured ? 'Supabase no responde a la consulta de prueba'
    : 'Falta configurar el almacén persistente';

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white">Captura empírica de autenticación</h2>
            <p className="text-xs text-slate-400 mt-1">Eventos observados y almacenados en Supabase. No incluye tráfico del simulador ni datasets CICIDS.</p>
          </div>
          <button onClick={() => void load()} disabled={loading || action !== null} className="px-4 py-2 rounded-xl bg-slate-800 border border-slate-700 text-slate-200 text-xs font-semibold hover:bg-slate-700 disabled:opacity-50">
            Actualizar estado
          </button>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="bg-slate-950 rounded-xl border border-slate-800 p-4">
            <p className="text-[10px] uppercase font-bold text-slate-500">Conexión</p>
            <p className={`text-sm font-bold mt-1 ${health?.supabase_ok ? 'text-emerald-400' : 'text-amber-400'}`}>{statusText}</p>
          </div>
          <div className="bg-slate-950 rounded-xl border border-slate-800 p-4">
            <p className="text-[10px] uppercase font-bold text-slate-500">Almacén configurado</p>
            <p className={`text-sm font-bold mt-1 ${health?.event_store?.configured ? 'text-emerald-400' : 'text-rose-400'}`}>{health?.event_store?.configured ? 'Sí' : 'No'}</p>
          </div>
          <div className="bg-slate-950 rounded-xl border border-slate-800 p-4">
            <p className="text-[10px] uppercase font-bold text-slate-500">Captura interna</p>
            <p className={`text-sm font-bold mt-1 ${captureReady ? 'text-emerald-400' : 'text-amber-400'}`}>{captureReady ? 'Lista' : 'Pendiente de experimento'}</p>
          </div>
          <div className="bg-slate-950 rounded-xl border border-slate-800 p-4">
            <p className="text-[10px] uppercase font-bold text-slate-500">Integración externa</p>
            <p className={`text-sm font-bold mt-1 ${health?.backend_integration_ready ? 'text-emerald-400' : 'text-slate-300'}`}>{health?.backend_integration_ready ? 'Lista' : 'No verificada'}</p>
          </div>
        </div>
        {health?.capture_paused && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-300">
            Captura pausada: {health.capture_pause_reason || 'Se detectó un problema de persistencia.'}
          </div>
        )}
      </div>

      {error && <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-300">{error}</div>}
      {notice && <div role="status" className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">{notice}</div>}

      {!experiment ? (
        <form onSubmit={createExperiment} className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
          <div>
            <h3 className="text-base font-bold text-white">Crear experimento</h3>
            <p className="text-xs text-slate-400 mt-1">Define los cortes temporales antes de recopilar y observar resultados. Todas las fechas se convierten a UTC al guardarse.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="text-xs text-slate-300 space-y-1">
              <span className="block font-semibold">Nombre del protocolo</span>
              <input value={protocolName} onChange={(e) => setProtocolName(e.target.value)} required maxLength={120} className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white" />
            </label>
            <label className="text-xs text-slate-300 space-y-1">
              <span className="block font-semibold">Escenario de captura</span>
              <input value={scenario} onChange={(e) => setScenario(e.target.value)} required maxLength={120} className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white" />
            </label>
            <label className="text-xs text-slate-300 space-y-1">
              <span className="block font-semibold">Fin de entrenamiento (hora local)</span>
              <input type="datetime-local" value={trainEndAt} onChange={(e) => setTrainEndAt(e.target.value)} required className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white" />
            </label>
            <label className="text-xs text-slate-300 space-y-1">
              <span className="block font-semibold">Fin de validación (hora local)</span>
              <input type="datetime-local" value={validationEndAt} onChange={(e) => setValidationEndAt(e.target.value)} required className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white" />
            </label>
          </div>
          <label className="block text-xs text-slate-300 space-y-1">
            <span className="font-semibold">Descripción y alcance</span>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} maxLength={1000} className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white" />
          </label>
          <p className="text-[11px] text-amber-300">No crees el experimento hasta definir las fechas y el escenario de forma consistente con tu protocolo de investigación. Una vez iniciado, los cortes no deben moverse al ver las métricas.</p>
          <button type="submit" disabled={loading || action !== null || !health?.supabase_ok || health?.capture_paused} className="px-5 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-bold disabled:opacity-50">
            {action === 'create' ? 'Creando…' : 'Crear experimento y habilitar captura'}
          </button>
        </form>
      ) : (
        <>
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
            <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-white">Experimento activo</h3>
                <p className="text-[11px] text-slate-400 font-mono mt-1 break-all">{experiment.id}</p>
              </div>
              <span className={`text-xs font-bold px-3 py-1 rounded-full w-fit ${experiment.trainingFrozen ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'bg-amber-500/10 text-amber-300 border border-amber-500/30'}`}>
                {experiment.trainingFrozen ? 'Baseline congelado' : 'Baseline pendiente'}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3">
                <p className="text-slate-500">Fin de entrenamiento</p>
                <p className="text-white font-semibold mt-1">{formatDate(experiment.trainEndMs)}</p>
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3">
                <p className="text-slate-500">Fin de validación</p>
                <p className="text-white font-semibold mt-1">{formatDate(experiment.validationEndMs)}</p>
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-2">
              {[
                ['Capturados', counts.total],
                ['Train', counts.train],
                ['Validación', counts.validation],
                ['Test', counts.test],
                ['Sin etiqueta', counts.unknown],
                ['Benignos', counts.benign],
                ['Ataques', counts.attack],
              ].map(([label, value]) => (
                <div key={label} className="bg-slate-950 border border-slate-800 rounded-xl p-3">
                  <p className="text-[10px] text-slate-500">{label}</p>
                  <p className="text-xl font-bold text-white mt-1">{value}</p>
                </div>
              ))}
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={trainModel} disabled={action !== null || experiment.trainingFrozen} className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold disabled:opacity-50">
                {action === 'train' ? 'Entrenando…' : 'Entrenar y congelar baseline'}
              </button>
              <button onClick={finishExperiment} disabled={action !== null} className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-xs font-bold disabled:opacity-50">
                Finalizar experimento
              </button>
              <button onClick={abortExperiment} disabled={action !== null} className="px-4 py-2 rounded-lg border border-rose-500/40 text-rose-300 hover:bg-rose-500/10 text-xs font-bold disabled:opacity-50">
                Abortar con motivo
              </button>
              <a href={`/api/dataset/capturado?experiment_id=${encodeURIComponent(experiment.id)}&formato=csv`} className="px-4 py-2 rounded-lg border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 text-xs font-bold">
                Exportar CSV
              </a>
              <a href={`/api/experimentos/metricas_capturadas?experiment_id=${encodeURIComponent(experiment.id)}`} target="_blank" rel="noreferrer" className="px-4 py-2 rounded-lg border border-slate-700 text-slate-200 hover:bg-slate-800 text-xs font-bold">
                Consultar métricas
              </a>
            </div>
            <p className="text-[11px] text-slate-500">Se requieren al menos 50 ventanas benignas etiquetadas para congelar el baseline. Las métricas finales solo se calculan sobre test etiquetado y con el baseline congelado.</p>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
            <div>
              <h3 className="text-base font-bold text-white">Revisión y etiquetado auditado</h3>
              <p className="text-xs text-slate-400 mt-1">Se muestran todos los eventos del experimento, ordenados del más reciente al más antiguo, en páginas de 20 registros. Las etiquetas deben basarse en registros de sesiones legítimas o manifiestos independientes de campañas autorizadas, nunca en las alertas de Centinela.</p>
            </div>
            {sortedEvents.length === 0 ? (
              <p className="text-sm text-slate-500">Todavía no hay eventos capturados. El ingreso ocurre mediante el login del testbed o desde un backend autorizado que invoque /registrar_intento.</p>
            ) : (
              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
                  <p className="text-xs text-slate-300">
                    Mostrando <strong className="text-white">{firstVisibleEvent}–{lastVisibleEvent}</strong> de <strong className="text-white">{sortedEvents.length}</strong> eventos · Página {eventPage} de {totalEventPages}
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setEventPage((page) => Math.max(1, page - 1))}
                      disabled={eventPage <= 1}
                      className="px-3 py-2 rounded-lg border border-slate-700 text-slate-200 text-xs font-semibold hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      Anterior
                    </button>
                    <button
                      type="button"
                      onClick={() => setEventPage((page) => Math.min(totalEventPages, page + 1))}
                      disabled={eventPage >= totalEventPages}
                      className="px-3 py-2 rounded-lg border border-cyan-500/40 text-cyan-200 text-xs font-semibold hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      Siguiente
                    </button>
                  </div>
                </div>
                {paginatedEvents.map((item) => {
                  const draft = drafts[item.event_id] ?? { method: '', rationale: '' };
                  return (
                    <div key={item.event_id} className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
                      <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-2">
                        <div>
                          <p className="text-[11px] text-slate-300 font-mono break-all">{item.event_id}</p>
                          <p className="text-xs text-slate-400 mt-1">{formatDate(item.occurred_at)} · {item.origin} · {item.dataset_split}</p>
                        </div>
                        <span className={`text-[10px] px-2 py-1 rounded-full w-fit font-bold ${item.ground_truth_label === 'unknown' ? 'bg-amber-500/10 text-amber-300' : item.ground_truth_label === 'attack' ? 'bg-rose-500/10 text-rose-300' : 'bg-emerald-500/10 text-emerald-300'}`}>
                          {item.ground_truth_label}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] text-slate-400">
                        <span>Autenticación: <b className={item.auth_success ? 'text-emerald-300' : 'text-slate-200'}>{item.auth_success ? 'exitosa' : 'fallida'}</b></span>
                        <span>Alerta reglas: <b className="text-slate-200">{item.alerta_reglas ? 'sí' : 'no'}</b></span>
                        <span>Alerta ML: <b className="text-slate-200">{item.alerta_ml ? 'sí' : 'no'}</b></span>
                        <span>Latencia: <b className="text-slate-200">{formatNumber(item.latency_total_ms)} ms</b></span>
                      </div>
                      <details className="text-[10px] text-slate-500">
                        <summary className="cursor-pointer">Ver identificadores seudonimizados</summary>
                        <p className="mt-2 break-all">IP HMAC: {item.source_ip_hash}</p>
                        <p className="mt-1 break-all">Usuario HMAC: {item.user_key_hash}</p>
                        {item.campaign_id && <p className="mt-1">Campaña: {item.campaign_id}</p>}
                      </details>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        <input value={draft.method} onChange={(e) => updateDraft(item.event_id, 'method', e.target.value)} placeholder="Método (p. ej. manifiesto de campaña)" maxLength={120} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white" />
                        <input value={draft.rationale} onChange={(e) => updateDraft(item.event_id, 'rationale', e.target.value)} placeholder="Evidencia que justifica la etiqueta" maxLength={1000} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white" />
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <button onClick={() => void labelEvent(item, 'benign')} disabled={action !== null || !draft.method.trim() || !draft.rationale.trim()} className="px-3 py-2 rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white text-[11px] font-bold disabled:opacity-40">Etiquetar benigno</button>
                        <button onClick={() => void labelEvent(item, 'attack')} disabled={action !== null || !draft.method.trim() || !draft.rationale.trim()} className="px-3 py-2 rounded-lg bg-rose-700 hover:bg-rose-600 text-white text-[11px] font-bold disabled:opacity-40">Etiquetar ataque</button>
                      </div>
                    </div>
                  );
                })}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950 px-4 py-3">
                  <p className="text-xs text-slate-300">
                    Mostrando <strong className="text-white">{firstVisibleEvent}–{lastVisibleEvent}</strong> de <strong className="text-white">{sortedEvents.length}</strong> eventos · Página {eventPage} de {totalEventPages}
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setEventPage((page) => Math.max(1, page - 1))}
                      disabled={eventPage <= 1}
                      className="px-3 py-2 rounded-lg border border-slate-700 text-slate-200 text-xs font-semibold hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      Anterior
                    </button>
                    <button
                      type="button"
                      onClick={() => setEventPage((page) => Math.min(totalEventPages, page + 1))}
                      disabled={eventPage >= totalEventPages}
                      className="px-3 py-2 rounded-lg border border-cyan-500/40 text-cyan-200 text-xs font-semibold hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      Siguiente
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
