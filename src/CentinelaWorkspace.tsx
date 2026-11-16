import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { EmpiricalStudyPanel } from './EmpiricalStudyPanel';

type WorkspaceSection = 'home' | 'monitor' | 'analytics' | 'cycle' | 'docs';
type CycleTab = 'overview' | 'data' | 'training' | 'validation' | 'test' | 'results';
type GroundTruth = 'unknown' | 'benign' | 'attack';

interface CapturedEvent {
  event_id: string;
  occurred_at: string;
  auth_success: boolean;
  origin: string;
  ground_truth_label: GroundTruth;
  dataset_split: 'unassigned' | 'train' | 'validation' | 'test';
  alerta_reglas: boolean;
  alerta_ml: boolean;
  alerta_iforest?: boolean;
  latency_total_ms: number | null;
}

interface ExperimentState {
  id: string;
  trainEndMs: number;
  validationEndMs: number;
  trainingFrozen: boolean;
}

interface HealthState {
  status?: string;
  db_ok?: boolean;
  supabase_ok?: boolean;
  capture_ready?: boolean;
  backend_integration_ready?: boolean;
  capture_paused?: boolean;
  capture_pause_reason?: string | null;
  event_store?: { configured?: boolean; clientConfigured?: boolean; hashSecretConfigured?: boolean };
}

interface MetricState {
  total_captured_events?: number;
  train_events?: number;
  validation_events?: number;
  test_events?: number;
  labeled_events?: number;
  unknown_events?: number;
  benign_events?: number;
  attack_events?: number;
  baseline_frozen?: boolean;
  metrics?: Record<string, {
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    precision: number;
    recall: number;
    f1: number;
    false_positive_rate: number | null;
  }> | null;
  latency?: {
    rules_mean_ms?: number | null;
    ml_mean_ms?: number | null;
    total_mean_ms?: number | null;
    sample_size?: number;
  };
  note?: string;
}

interface Snapshot {
  health: HealthState | null;
  experiment: ExperimentState | null;
  events: CapturedEvent[];
  metrics: MetricState | null;
  error: string | null;
  loading: boolean;
  refreshedAt: number | null;
}

const CYCLE_TABS: Array<{ id: CycleTab; label: string }> = [
  { id: 'overview', label: 'Resumen' },
  { id: 'data', label: 'Datos y auditoría' },
  { id: 'training', label: 'Entrenamiento' },
  { id: 'validation', label: 'Validación' },
  { id: 'test', label: 'Prueba' },
  { id: 'results', label: 'Resultados' },
];

async function readJson(response: Response): Promise<any> {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || 'No se pudo consultar el estado de Centinela.');
  return payload;
}

function dateLabel(value: number | string | null | undefined): string {
  if (value === null || value === undefined) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function metricLabel(value: number | null | undefined, digits = 2): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : '—';
}

function StatCard({ label, value, helper, tone = 'default' }: {
  label: string;
  value: string | number;
  helper?: string;
  tone?: 'default' | 'good' | 'warning';
}) {
  const valueTone = tone === 'good' ? 'text-emerald-300' : tone === 'warning' ? 'text-amber-300' : 'text-white';
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 min-w-0">
      <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
      <p className={'mt-1 text-2xl font-extrabold tabular-nums ' + valueTone}>{value}</p>
      {helper && <p className="mt-1 text-[11px] text-slate-500">{helper}</p>}
    </div>
  );
}

function StatusPill({ children, tone = 'neutral' }: {
  children: React.ReactNode;
  tone?: 'good' | 'warning' | 'bad' | 'neutral';
}) {
  const classes = tone === 'good'
    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
    : tone === 'warning'
      ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
      : tone === 'bad'
        ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
        : 'border-slate-700 bg-slate-800 text-slate-300';
  return <span className={'inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-bold ' + classes}>{children}</span>;
}

function SectionTitle({ title, description, action }: {
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h2 className="text-lg font-bold text-white">{title}</h2>
        <p className="mt-1 text-xs text-slate-400">{description}</p>
      </div>
      {action}
    </div>
  );
}

function EmptyState({ children }: { children: React.ReactNode }) {
  return <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/60 p-6 text-sm text-slate-400">{children}</div>;
}

function EventRows({ events, compact = false }: { events: CapturedEvent[]; compact?: boolean }) {
  if (events.length === 0) return <EmptyState>No hay eventos persistidos para el experimento activo.</EmptyState>;
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800">
      <table className="w-full min-w-[760px] text-left text-xs">
        <thead className="bg-slate-950 text-slate-400">
          <tr>
            <th className="px-3 py-3 font-semibold">Fecha</th>
            <th className="px-3 py-3 font-semibold">Autenticación</th>
            <th className="px-3 py-3 font-semibold">Etiqueta auditada</th>
            <th className="px-3 py-3 font-semibold">Conjunto</th>
            <th className="px-3 py-3 font-semibold">Alerta reglas</th>
            <th className="px-3 py-3 font-semibold">Alerta ML</th>
            {!compact && <th className="px-3 py-3 font-semibold">Latencia</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 bg-slate-900/60">
          {events.map((event) => (
            <tr key={event.event_id}>
              <td className="px-3 py-3 text-slate-300 whitespace-nowrap">{dateLabel(event.occurred_at)}</td>
              <td className="px-3 py-3">
                <StatusPill tone={event.auth_success ? 'good' : 'warning'}>{event.auth_success ? 'Exitosa' : 'Fallida'}</StatusPill>
              </td>
              <td className="px-3 py-3">
                <StatusPill tone={event.ground_truth_label === 'benign' ? 'good' : event.ground_truth_label === 'attack' ? 'bad' : 'warning'}>
                  {event.ground_truth_label === 'benign' ? 'Benigno' : event.ground_truth_label === 'attack' ? 'Ataque' : 'Sin etiqueta'}
                </StatusPill>
              </td>
              <td className="px-3 py-3 text-slate-300 uppercase">{event.dataset_split}</td>
              <td className="px-3 py-3 text-slate-300">{event.alerta_reglas ? 'Sí' : 'No'}</td>
              <td className="px-3 py-3 text-slate-300">{event.alerta_ml ? 'Sí' : 'No'}</td>
              {!compact && <td className="px-3 py-3 text-slate-300">{metricLabel(event.latency_total_ms)} ms</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CentinelaWorkspace({ section }: { section: WorkspaceSection }) {
  const [cycleTab, setCycleTab] = useState<CycleTab>('overview');
  const [snapshot, setSnapshot] = useState<Snapshot>({
    health: null,
    experiment: null,
    events: [],
    metrics: null,
    error: null,
    loading: true,
    refreshedAt: null,
  });

  const refresh = useCallback(async () => {
    if (section === 'docs') {
      setSnapshot((current) => ({ ...current, loading: false }));
      return;
    }
    setSnapshot((current) => ({ ...current, loading: true, error: null }));
    try {
      const [healthResponse, stateResponse] = await Promise.all([
        fetch('/health', { credentials: 'same-origin', cache: 'no-store' }),
        fetch('/api/experimentos/estado', { credentials: 'same-origin', cache: 'no-store' }),
      ]);
      const [health, state] = await Promise.all([readJson(healthResponse), readJson(stateResponse)]);
      const experiment = (state.active_experiment ?? null) as ExperimentState | null;
      let events: CapturedEvent[] = [];
      let metrics: MetricState | null = null;

      if (experiment?.id) {
        const eventsResponse = await fetch(
          '/api/dataset/capturado?experiment_id=' + encodeURIComponent(experiment.id),
          { credentials: 'same-origin', cache: 'no-store' }
        );
        const eventsPayload = await readJson(eventsResponse);
        events = Array.isArray(eventsPayload.events) ? eventsPayload.events : [];

        if (section === 'cycle' && (cycleTab === 'test' || cycleTab === 'results')) {
          const metricsResponse = await fetch(
            '/api/experimentos/metricas_capturadas?experiment_id=' + encodeURIComponent(experiment.id),
            { credentials: 'same-origin', cache: 'no-store' }
          );
          metrics = await readJson(metricsResponse);
        }
      }

      setSnapshot({
        health,
        experiment,
        events,
        metrics,
        error: null,
        loading: false,
        refreshedAt: Date.now(),
      });
    } catch (error) {
      setSnapshot((current) => ({
        ...current,
        loading: false,
        error: error instanceof Error ? error.message : 'No se pudo actualizar el espacio de trabajo.',
      }));
    }
  }, [section, cycleTab]);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), 30000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  const counts = useMemo(() => {
    const result = {
      total: snapshot.events.length,
      train: 0, validation: 0, test: 0,
      trainBenign: 0, trainUnknown: 0,
      benign: 0, attack: 0, unknown: 0,
      successful: 0, failed: 0, ruleAlerts: 0, mlAlerts: 0,
    };
    for (const event of snapshot.events) {
      if (event.dataset_split === 'train') {
        result.train++;
        if (event.ground_truth_label === 'benign') result.trainBenign++;
        if (event.ground_truth_label === 'unknown') result.trainUnknown++;
      }
      if (event.dataset_split === 'validation') result.validation++;
      if (event.dataset_split === 'test') result.test++;
      if (event.ground_truth_label === 'benign') result.benign++;
      if (event.ground_truth_label === 'attack') result.attack++;
      if (event.ground_truth_label === 'unknown') result.unknown++;
      if (event.auth_success) result.successful++;
      else result.failed++;
      if (event.alerta_reglas) result.ruleAlerts++;
      if (event.alerta_ml) result.mlAlerts++;
    }
    return result;
  }, [snapshot.events]);

  const experiment = snapshot.experiment;
  const now = Date.now();
  const trainClosed = Boolean(experiment && now >= experiment.trainEndMs);
  const validationStarted = Boolean(experiment && now >= experiment.trainEndMs);
  const validationClosed = Boolean(experiment && now >= experiment.validationEndMs);
  const testStarted = validationClosed;
  const baselineFrozen = experiment?.trainingFrozen === true;
  const currentPhase = !experiment
    ? 'Sin experimento activo'
    : !trainClosed
      ? 'Recopilación de entrenamiento'
      : !baselineFrozen && !validationClosed
        ? 'Entrenamiento pendiente de congelación'
        : !validationClosed
          ? 'Validación'
          : 'Prueba';

  const cardClass = 'rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl space-y-3';
  const sectionTabs = section === 'cycle' ? (
    <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
      {CYCLE_TABS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => setCycleTab(tab.id)}
          className={'rounded-lg border px-3 py-2 text-xs font-semibold transition-colors ' +
            (cycleTab === tab.id
              ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200'
              : 'border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-600 hover:text-white')}
        >
          {tab.label}
        </button>
      ))}
    </div>
  ) : null;

  return (
    <div className="space-y-5">
      {section !== 'docs' && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-[11px] text-slate-500">
            {snapshot.refreshedAt ? 'Última actualización: ' + dateLabel(snapshot.refreshedAt) : 'Consultando fuentes persistentes…'}
            <span className="ml-2">· Actualización automática cada 30 segundos</span>
          </div>
          <button type="button" onClick={() => void refresh()} disabled={snapshot.loading} className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 disabled:opacity-50">
            {snapshot.loading ? 'Actualizando…' : 'Actualizar vista'}
          </button>
        </div>
      )}

      {snapshot.error && <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-300">{snapshot.error}</div>}

      {section === 'home' && (
        <div className="space-y-5">
          <div className={cardClass}>
            <SectionTitle title="Resumen ejecutivo" description="Estado operativo de Centinela y actividad del experimento activo. Los indicadores se consultan en modo de solo lectura." />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard label="Servicio Centinela" value={snapshot.health?.status === 'ok' ? 'Operativo' : snapshot.health?.status || '—'} tone={snapshot.health?.status === 'ok' ? 'good' : 'warning'} helper="Comprobación del endpoint /health" />
              <StatCard label="Supabase" value={snapshot.health?.supabase_ok ? 'Conectado' : 'No verificado'} tone={snapshot.health?.supabase_ok ? 'good' : 'warning'} helper="Almacén persistente" />
              <StatCard label="Eventos del experimento" value={snapshot.loading ? '…' : counts.total} helper="Eventos reales persistidos" />
              <StatCard label="Alertas observadas" value={snapshot.loading ? '…' : counts.ruleAlerts + counts.mlAlerts} helper="Suma de indicadores de reglas y ML; puede contar un evento dos veces" />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
            <div className={cardClass + ' xl:col-span-2'}>
              <SectionTitle title="Estado del ciclo de ML" description="Progreso basado en los cortes temporales registrados y el estado de congelación del baseline." />
              <div className="flex flex-wrap items-center gap-2">
                <StatusPill tone={experiment ? (baselineFrozen ? 'good' : 'warning') : 'neutral'}>{currentPhase}</StatusPill>
                <StatusPill tone={snapshot.health?.capture_paused ? 'bad' : snapshot.health?.capture_ready ? 'good' : 'neutral'}>
                  {snapshot.health?.capture_paused ? 'Captura pausada' : snapshot.health?.capture_ready ? 'Captura lista' : 'Captura no verificada'}
                </StatusPill>
              </div>
              {experiment ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="rounded-xl bg-slate-950 p-3">
                    <p className="text-[10px] uppercase text-slate-500">Fin de entrenamiento</p>
                    <p className="mt-1 text-sm font-semibold text-white">{dateLabel(experiment.trainEndMs)}</p>
                  </div>
                  <div className="rounded-xl bg-slate-950 p-3">
                    <p className="text-[10px] uppercase text-slate-500">Fin de validación</p>
                    <p className="mt-1 text-sm font-semibold text-white">{dateLabel(experiment.validationEndMs)}</p>
                  </div>
                </div>
              ) : <EmptyState>No existe un experimento activo. El resumen no utilizará conjuntos históricos como si fueran el experimento actual.</EmptyState>}
            </div>
            <div className={cardClass}>
              <SectionTitle title="Distribución de eventos" description="Conteos del experimento activo." />
              <div className="space-y-3">
                {[
                  ['Entrenamiento', counts.train],
                  ['Validación', counts.validation],
                  ['Prueba', counts.test],
                  ['Sin etiqueta', counts.unknown],
                ].map(([label, value]) => (
                  <div key={label} className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">{label}</span>
                    <strong className="text-white tabular-nums">{snapshot.loading ? '…' : value}</strong>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className={cardClass}>
            <SectionTitle title="Actividad reciente" description="Los registros se leen directamente del conjunto persistido en Supabase." />
            <EventRows events={[...snapshot.events].sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at)).slice(0, 6)} compact />
          </div>
        </div>
      )}

      {section === 'monitor' && (
        <div className={cardClass}>
          <SectionTitle title="Monitor de autenticación" description="Eventos persistidos del experimento activo, sin acciones de bloqueo ni modificación desde esta pantalla." />
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatCard label="Eventos" value={counts.total} />
            <StatCard label="Autenticaciones exitosas" value={counts.successful} tone="good" />
            <StatCard label="Autenticaciones fallidas" value={counts.failed} tone="warning" />
            <StatCard label="Alertas ML" value={counts.mlAlerts} tone={counts.mlAlerts ? 'warning' : 'default'} />
          </div>
          {!experiment && <EmptyState>No hay un experimento activo para consultar. Los datos históricos permanecen separados.</EmptyState>}
          {experiment && <EventRows events={[...snapshot.events].sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at)).slice(0, 100)} />}
        </div>
      )}

      {section === 'analytics' && (
        <div className="space-y-5">
          <div className={cardClass}>
            <SectionTitle title="Analítica de autenticación" description="Estadísticas descriptivas del experimento activo. No son métricas de rendimiento del clasificador." />
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <StatCard label="Eventos capturados" value={counts.total} />
              <StatCard label="Benignos etiquetados" value={counts.benign} tone="good" />
              <StatCard label="Ataques etiquetados" value={counts.attack} tone="warning" />
              <StatCard label="Pendientes de etiqueta" value={counts.unknown} />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <div className={cardClass}>
              <SectionTitle title="Distribución temporal" description="Cantidad de eventos asignados a cada conjunto." />
              {[
                ['Train', counts.train],
                ['Validation', counts.validation],
                ['Test', counts.test],
              ].map(([label, value]) => {
                const pct = counts.total ? Math.round((Number(value) / counts.total) * 100) : 0;
                return (
                  <div key={label} className="space-y-1">
                    <div className="flex justify-between text-xs"><span className="text-slate-400">{label}</span><span className="text-white">{value} · {pct}%</span></div>
                    <div className="h-2 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-cyan-500" style={{ width: pct + '%' }} /></div>
                  </div>
                );
              })}
            </div>
            <div className={cardClass}>
              <SectionTitle title="Resultado de autenticación" description="Éxitos y fallos observados, sin inferir por sí solos si son benignos o ataques." />
              {[
                ['Exitosas', counts.successful, 'bg-emerald-500'],
                ['Fallidas', counts.failed, 'bg-amber-500'],
              ].map(([label, value, color]) => {
                const pct = counts.total ? Math.round((Number(value) / counts.total) * 100) : 0;
                return (
                  <div key={label} className="space-y-1">
                    <div className="flex justify-between text-xs"><span className="text-slate-400">{label}</span><span className="text-white">{value} · {pct}%</span></div>
                    <div className="h-2 overflow-hidden rounded-full bg-slate-800"><div className={'h-full rounded-full ' + color} style={{ width: pct + '%' }} /></div>
                  </div>
                );
              })}
            </div>
          </div>
          <div className={cardClass}>
            <SectionTitle title="Señales del detector" description="Indicadores presentes en los eventos. Una alerta del detector no constituye ground truth." />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <StatCard label="Alertas por reglas" value={counts.ruleAlerts} />
              <StatCard label="Alertas ML" value={counts.mlAlerts} />
            </div>
          </div>
        </div>
      )}

      {section === 'cycle' && (
        <div className="space-y-5">
          <div className={cardClass}>
            <SectionTitle title="Ciclo de aprendizaje automático" description="Seguimiento de captura, entrenamiento, validación, prueba y resultados reproducibles." />
            {sectionTabs}
            {!experiment && <EmptyState>No hay un experimento activo. El espacio no combinará automáticamente los experimentos v1 y v2.</EmptyState>}
            {experiment && (
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
                <StatCard label="Capturados" value={counts.total} />
                <StatCard label="Train" value={counts.train} />
                <StatCard label="Validación" value={counts.validation} />
                <StatCard label="Test" value={counts.test} />
                <StatCard label="Baseline" value={baselineFrozen ? 'Congelado' : 'Pendiente'} tone={baselineFrozen ? 'good' : 'warning'} />
              </div>
            )}
          </div>

          {cycleTab === 'overview' && experiment && (
            <div className={cardClass}>
              <SectionTitle title="Resumen del experimento" description="El estado se calcula con los cortes preregistrados y los metadatos del baseline." />
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs font-bold text-slate-300">1. Datos y etiquetado</p>
                  <p className="mt-1 text-xs text-slate-400">{counts.total} eventos · {counts.unknown} pendientes de etiqueta.</p>
                  <StatusPill tone={counts.total > 0 ? 'good' : 'neutral'}>{counts.total > 0 ? 'Hay datos capturados' : 'Sin datos'}</StatusPill>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs font-bold text-slate-300">2. Entrenamiento</p>
                  <p className="mt-1 text-xs text-slate-400">{counts.trainBenign} eventos benignos etiquetados en train; mínimo orientativo: 50 ventanas.</p>
                  <StatusPill tone={baselineFrozen ? 'good' : 'warning'}>{baselineFrozen ? 'Baseline congelado' : trainClosed ? 'Corte alcanzado; congelación pendiente' : 'Recopilación abierta'}</StatusPill>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs font-bold text-slate-300">3. Validación</p>
                  <p className="mt-1 text-xs text-slate-400">{counts.validation} eventos asignados al periodo de validación.</p>
                  <StatusPill tone={validationStarted && !validationClosed ? 'warning' : validationClosed ? 'neutral' : 'neutral'}>{validationClosed ? 'Periodo cerrado' : validationStarted ? 'Periodo abierto' : 'Pendiente'}</StatusPill>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs font-bold text-slate-300">4. Prueba</p>
                  <p className="mt-1 text-xs text-slate-400">{counts.test} eventos asignados al periodo de prueba.</p>
                  <StatusPill tone={testStarted ? 'warning' : 'neutral'}>{testStarted ? 'Periodo abierto' : 'Pendiente'}</StatusPill>
                </div>
              </div>
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 text-xs leading-5 text-slate-300">
                La asignación train/validation/test procede de las fechas guardadas en el experimento. Esta vista es informativa: no cambia fechas, etiquetas, datos ni parámetros del detector.
              </div>
            </div>
          )}

          {cycleTab === 'data' && (
            <div className="space-y-3">
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-xs text-slate-400">
                La captura empírica existente se conserva aquí. Esta pantalla mantiene sus acciones auditadas de etiquetado, entrenamiento, cierre y exportación; no se ha reemplazado su lógica.
              </div>
              <EmpiricalStudyPanel />
            </div>
          )}

          {cycleTab === 'training' && experiment && (
            <div className={cardClass}>
              <SectionTitle title="Entrenamiento del baseline" description="El baseline se construye solo con ventanas benignas confirmadas del conjunto train." />
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <StatCard label="Eventos benignos train" value={counts.trainBenign} helper="Conteo de eventos; el servidor valida el número exacto de ventanas" tone={counts.trainBenign >= 50 ? 'good' : 'warning'} />
                <StatCard label="Mínimo requerido" value="50" helper="Ventanas benignas" />
                <StatCard label="Estado del baseline" value={baselineFrozen ? 'Congelado' : 'Pendiente'} tone={baselineFrozen ? 'good' : 'warning'} />
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-300 space-y-2">
                <p>El entrenamiento solo puede ejecutarse después del cierre del periodo train y antes de que comience el periodo test. El endpoint del servidor verifica estas condiciones y calcula las ventanas válidas.</p>
                <p className="text-xs text-slate-500">Para ejecutar o revisar la acción auditada, utiliza «Datos y auditoría», donde permanece el botón original «Entrenar y congelar baseline».</p>
                {baselineFrozen && <p className="text-emerald-300 text-xs">El baseline ya está congelado para este experimento; no se volverá a entrenar.</p>}
              </div>
            </div>
          )}

          {cycleTab === 'validation' && experiment && (
            <div className={cardClass}>
              <SectionTitle title="Validación del modelo" description="La validación sirve para calibrar umbrales y seleccionar parámetros antes de la prueba final." />
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <StatCard label="Eventos validation" value={counts.validation} />
                <StatCard label="Benignos globales" value={counts.benign} />
                <StatCard label="Ataques globales" value={counts.attack} />
              </div>
              <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs leading-5 text-slate-300">
                La interfaz muestra la cantidad de observaciones, pero la calibración científica de los modelos se realiza con el evaluador reproducible independiente. Para ejecutarla se requiere que validation contenga ejemplos etiquetados de ambas clases. No se publican métricas de validación inventadas ni se modifica el baseline desde esta pantalla.
              </div>
            </div>
          )}

          {cycleTab === 'test' && experiment && (
            <div className={cardClass}>
              <SectionTitle title="Prueba final" description="Resultados del conjunto temporal test. No se reajusta el modelo ni el umbral con estos eventos." />
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <StatCard label="Eventos test" value={counts.test} />
                <StatCard label="Benignos test" value={snapshot.events.filter((event) => event.dataset_split === 'test' && event.ground_truth_label === 'benign').length} />
                <StatCard label="Ataques test" value={snapshot.events.filter((event) => event.dataset_split === 'test' && event.ground_truth_label === 'attack').length} />
              </div>
              {!baselineFrozen && <EmptyState>La prueba no puede presentarse como evaluación final: el baseline todavía no está congelado.</EmptyState>}
              {baselineFrozen && counts.test === 0 && <EmptyState>Aún no hay eventos en el periodo de prueba.</EmptyState>}
              {snapshot.metrics?.metrics && (
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="w-full min-w-[650px] text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400"><tr><th className="p-3">Detector</th><th className="p-3">Precision</th><th className="p-3">Recall</th><th className="p-3">F1</th><th className="p-3">Falsos positivos</th></tr></thead>
                    <tbody className="divide-y divide-slate-800">
                      {Object.entries(snapshot.metrics.metrics).map(([name, metric]) => (
                        <tr key={name}><td className="p-3 text-slate-200">{name}</td><td className="p-3 text-slate-300">{metricLabel(metric.precision)}</td><td className="p-3 text-slate-300">{metricLabel(metric.recall)}</td><td className="p-3 text-slate-300">{metricLabel(metric.f1)}</td><td className="p-3 text-slate-300">{metric.fp}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {snapshot.metrics?.note && <p className="text-xs text-slate-500">{snapshot.metrics.note}</p>}
              <p className="text-[11px] text-slate-500">Las métricas anteriores, cuando estén disponibles, corresponden a decisiones del detector Node en el test. La comparación canónica con scikit-learn se conserva en el evaluador offline y debe identificarse por separado.</p>
            </div>
          )}

          {cycleTab === 'results' && experiment && (
            <div className={cardClass}>
              <SectionTitle title="Resultados y evidencias reproducibles" description="Archivos previstos para presentar y auditar el experimento." />
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><p className="font-semibold text-white">empirical_metrics.json</p><p className="mt-1 text-xs text-slate-400">Métricas, conteos, versiones y protocolo de evaluación.</p></div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><p className="font-semibold text-white">test_predictions.csv</p><p className="mt-1 text-xs text-slate-400">Predicciones individuales del conjunto test.</p></div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><p className="font-semibold text-white">empirical_manifest.json</p><p className="mt-1 text-xs text-slate-400">Hashes de los datos, script, resultados y commit.</p></div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-2">
                <p className="text-sm font-semibold text-white">Evaluador reproducible</p>
                <p className="text-xs leading-5 text-slate-400">El repositorio incluye «empirical_auth_evaluation.py». Actualmente se ejecuta fuera del servidor web después de exportar el CSV. Exige 50 o más ventanas benignas train y ambas clases etiquetadas en validation y test. Esta pestaña no ejecuta el script ni modifica el experimento.</p>
                <a className="inline-flex rounded-lg border border-cyan-500/40 px-3 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/10" href={'/api/dataset/capturado?experiment_id=' + encodeURIComponent(experiment.id) + '&formato=csv'}>Descargar CSV del experimento</a>
              </div>
              {snapshot.metrics?.metrics && <p className="text-xs text-emerald-300">Hay métricas del detector Node disponibles en el endpoint de métricas del experimento. No sustituyen los artefactos del evaluador externo.</p>}
            </div>
          )}
        </div>
      )}

      {section === 'docs' && (
        <div className="space-y-5">
          <div className={cardClass}>
            <SectionTitle title="Documentación de Centinela" description="Descripción de la arquitectura, operación y metodología experimental." />
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><h3 className="font-semibold text-white">Arquitectura</h3><p className="mt-2 text-xs leading-5 text-slate-400">Aplicación web React, servidor Node/Express, motor de reglas y componentes de detección de anomalías. Supabase conserva los experimentos, eventos y el historial de etiquetado.</p></div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><h3 className="font-semibold text-white">Integración de autenticación</h3><p className="mt-2 text-xs leading-5 text-slate-400">Los eventos externos deben llegar desde un backend de autenticación confiable mediante el endpoint protegido de ingesta. Las contraseñas no forman parte del registro de Centinela.</p></div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><h3 className="font-semibold text-white">Protección de datos</h3><p className="mt-2 text-xs leading-5 text-slate-400">Los identificadores de IP y usuario se seudonimizan mediante HMAC. Las credenciales y secretos permanecen en variables de entorno del servidor.</p></div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><h3 className="font-semibold text-white">Metodología empírica</h3><p className="mt-2 text-xs leading-5 text-slate-400">La división temporal se fija antes de la observación. El baseline usa únicamente ventanas benignas train; validation se reserva para calibración y test para la evaluación final independiente.</p></div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><h3 className="font-semibold text-white">Etiquetado y ground truth</h3><p className="mt-2 text-xs leading-5 text-slate-400">Las etiquetas requieren evidencia independiente. Una autenticación fallida o una alerta del detector no demuestran, por sí solas, que exista un ataque.</p></div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4"><h3 className="font-semibold text-white">Reproducibilidad</h3><p className="mt-2 text-xs leading-5 text-slate-400">Se conservan el CSV de entrada, las predicciones, las métricas, los hashes, las versiones del entorno, los límites temporales y el commit del código.</p></div>
            </div>
          </div>
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs leading-5 text-slate-300">
            Esta documentación resume las capacidades implementadas en la rama experimental. No representa una certificación de seguridad ni afirma que las métricas finales ya hayan sido obtenidas.
          </div>
        </div>
      )}
    </div>
  );
}
