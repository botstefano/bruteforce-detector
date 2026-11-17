import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { io } from 'socket.io-client';

type ScenarioId = 'benign_mixed' | 'attack_rapid' | 'attack_low_frequency' | 'attack_distributed';

interface LabAgent {
  agent_id: string;
  egress_ip_hash_prefix: string;
  status: string;
  last_seen_at: string;
  current_job_id: string | null;
  version: string;
}

interface LabJob {
  job_id: string;
  run_id: string;
  scenario_id: ScenarioId;
  agent_id: string | null;
  status: string;
  attempts_completed: number;
  attempts_planned: number;
  start_at: string;
  expected_label: 'benign' | 'attack';
  summary?: Record<string, unknown>;
}

interface LabCampaign {
  campaign_id: string;
  experiment_id: string;
  status: string;
  target_account: string;
  scenario_ids: ScenarioId[];
  repetitions: number;
  phase: 'train' | 'validation' | 'test';
  jobs: LabJob[];
}

interface ExperimentPhaseState {
  id: string;
  trainEndMs: number;
  validationEndMs: number;
  testEndMs: number | null;
  trainingFrozen: boolean;
  validationFrozen: boolean;
}

interface LabSnapshot {
  generated_at: string;
  experiment_id: string | null;
  experiment: ExperimentPhaseState | null;
  agent_token_configured: boolean;
  protocol_revision?: number | null;
  automation?: {
    enabled: boolean;
    status: 'running' | 'paused' | 'completed';
    batchSize: number;
    lastError: string | null;
    targets: Record<string, Record<string, number>>;
  } | null;
  agents: LabAgent[];
  campaigns: LabCampaign[];
  scenarios: Array<{ scenario_id: ScenarioId; label: string; description: string; required_agents: number }>;
}

interface LiveEvent {
  event_id?: string;
  timestamp?: number;
  ip?: string;
  usuario?: string;
  exitoso?: boolean;
  alerta_reglas?: boolean;
  alerta_ml?: boolean;
  score_ml?: number;
  latency_total_ms?: number;
  campaign_id?: string | null;
  metadata?: { agent_id?: string | null; run_id?: string | null; scenario_id?: string | null };
}

const SCENARIO_LABELS: Record<ScenarioId, string> = {
  benign_mixed: 'Actividad legítima con errores ocasionales',
  attack_rapid: 'Fuerza bruta desde un origen',
  attack_low_frequency: 'Intentos de baja frecuencia',
  attack_distributed: 'Fuerza bruta distribuida (4 IP)',
};

async function readJson(response: Response): Promise<any> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function localDate(value: string | number | undefined): string {
  if (value === undefined) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function Pill({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'good' | 'warning' | 'bad' | 'neutral' }) {
  const styles = {
    good: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
    warning: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
    bad: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
    neutral: 'border-slate-700 bg-slate-800 text-slate-300',
  };
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-bold ${styles[tone]}`}>{children}</span>;
}

export function LabExperimentPanel() {
  const [snapshot, setSnapshot] = useState<LabSnapshot | null>(null);
  const [selected, setSelected] = useState<ScenarioId[]>(['benign_mixed', 'attack_rapid', 'attack_distributed']);
  const [targetAccount, setTargetAccount] = useState('ronan');
  const [repetitions, setRepetitions] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [agentLogs, setAgentLogs] = useState<Array<{ agent_id: string; message: string; timestamp: string }>>([]);
  const [connected, setConnected] = useState(false);
  const [protocolName, setProtocolName] = useState('centinela-auth-study-v4');
  const [scenario, setScenario] = useState('automated-authentication-testbed-v4');
  const [description, setDescription] = useState('Evaluación experimental reproducible mediante agentes automatizados en el portal autorizado de autenticación HTTP.');
  const [trainEndAt, setTrainEndAt] = useState('2026-12-01T17:00');
  const [validationEndAt, setValidationEndAt] = useState('2026-12-08T17:00');
  const [testEndAt, setTestEndAt] = useState('2026-12-15T17:00');

  const refresh = useCallback(async () => {
    try {
      const response = await fetch('/api/lab/state', { credentials: 'same-origin', cache: 'no-store' });
      const data = await readJson(response);
      setSnapshot(data as LabSnapshot);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo consultar el laboratorio.');
    }
  }, []);

  useEffect(() => {
    let socket: ReturnType<typeof io> | null = null;
    let interval: number | undefined;
    let disposed = false;
    fetch('/api/session', { credentials: 'same-origin', cache: 'no-store' })
      .then(async (response) => {
        if (!response.ok) throw new Error('La sesión administrativa ha caducado.');
        if (disposed) return;
        socket = io({ autoConnect: false, withCredentials: true });
        socket.on('connect', () => setConnected(true));
        socket.on('disconnect', () => setConnected(false));
        socket.on('connect_error', () => setConnected(false));
        socket.on('lab_agent_update', (data: LabSnapshot) => setSnapshot(data));
        socket.on('lab_campaign_update', (data: LabSnapshot) => setSnapshot(data));
        socket.on('nuevo_evento', (event: LiveEvent) => {
          setLiveEvents((current) => [event, ...current].slice(0, 80));
          void refresh();
        });
        socket.on('lab_agent_log', (entry: { agent_id: string; message: string; timestamp: string }) => {
          setAgentLogs((current) => [entry, ...current].slice(0, 80));
        });
        socket.connect();
        await refresh();
        interval = window.setInterval(() => void refresh(), 5000);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'No se pudo validar la sesión.'));
    return () => {
      disposed = true;
      if (interval) window.clearInterval(interval);
      socket?.disconnect();
    };
  }, [refresh]);

  const activeAgents = useMemo(
    () => (snapshot?.agents ?? []).filter((agent) => agent.status !== 'offline'),
    [snapshot]
  );
  const distinctOrigins = useMemo(
    () => new Set(activeAgents.map((agent) => agent.egress_ip_hash_prefix)).size,
    [activeAgents]
  );

  const toggleScenario = (scenario: ScenarioId) => {
    setSelected((current) => current.includes(scenario)
      ? current.filter((item) => item !== scenario)
      : [...current, scenario]);
  };

  const createExperiment = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const trainMs = new Date(trainEndAt).getTime();
      const validationMs = new Date(validationEndAt).getTime();
      const testMs = new Date(testEndAt).getTime();
      if (![trainMs, validationMs, testMs].every(Number.isFinite) || trainMs <= Date.now() || validationMs <= trainMs || testMs <= validationMs) {
        throw new Error('Los cortes deben ser futuros y seguir el orden entrenamiento < validación < test.');
      }
      const response = await fetch('/api/experimentos', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          protocol_name: protocolName,
          scenario,
          description,
          train_end_at: new Date(trainMs).toISOString(),
          validation_end_at: new Date(validationMs).toISOString(),
          test_end_at: new Date(testMs).toISOString(),
          metadata: {
            protocol_revision: 4,
            collection_design: 'variable_reproducible_sessions_with_phase_scheduler_v1',
            generation_profile_version: 2,
            independent_campaign_manifest: true,
            generation_method: 'automated_http_agent',
            actor_type: 'automated_agent',
            testbed_scope: 'centinela-auth-lab-only',
            phase_policy: 'train-benign-only_validation-freeze_before_test',
          },
        }),
      });
      const data = await readJson(response);
      setNotice(`Experimento V4 creado: ${data.experiment?.id || 'registrado'}. Los cortes quedaron guardados en UTC.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo crear el experimento v3.');
    } finally {
      setBusy(false);
    }
  };

  const createCampaign = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch('/api/lab/campaigns', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_ids: selected,
          target_account: targetAccount,
          repetitions,
        }),
      });
      const data = await readJson(response);
      setNotice(`Campaña ${data.campaign_id} creada y manifiesto guardado en el experimento.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo crear la campaña.');
    } finally {
      setBusy(false);
    }
  };


  const startAutomation = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch('/api/lab/automation/start', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ batch_size: 5, accounts: ['ronan', 'andy', 'stefano'] }),
      });
      const data = await readJson(response);
      setNotice('Recolección automática activada. El coordinador programará lotes variables y guardará el manifiesto antes de habilitar cada lote.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo iniciar la recolección automática.');
    } finally {
      setBusy(false);
    }
  };

  const stopAutomation = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await readJson(await fetch('/api/lab/automation/stop', {
        method: 'POST',
        credentials: 'same-origin',
      }));
      setNotice('La planificación automática se pausó. La campaña actualmente en ejecución no se cancela.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo pausar la recolección automática.');
    } finally {
      setBusy(false);
    }
  };

  const freezeValidation = async () => {
    if (!snapshot?.experiment_id) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(`/api/experimentos/${encodeURIComponent(snapshot.experiment_id)}/congelar_validacion`, {
        method: 'POST',
        credentials: 'same-origin',
      });
      const data = await readJson(response);
      setNotice(`Validación congelada: ${data.validation_benign_events} benignos y ${data.validation_attack_events} ataques. Configuración ${data.validation_config_version}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo congelar la configuración de validación.');
    } finally {
      setBusy(false);
    }
  };


  const finishExperiment = async () => {
    if (!snapshot?.experiment_id) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(`/api/experimentos/${encodeURIComponent(snapshot.experiment_id)}/finalizar`, {
        method: 'POST',
        credentials: 'same-origin',
      });
      await readJson(response);
      setNotice('Experimento finalizado. Ya puedes registrar un nuevo protocolo V4 independiente.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo finalizar el experimento.');
    } finally {
      setBusy(false);
    }
  };

  const campaignAction = async (campaignId: string, action: 'pause' | 'resume' | 'stop') => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(`/api/lab/campaigns/${encodeURIComponent(campaignId)}/${action}`, {
        method: 'POST',
        credentials: 'same-origin',
      });
      await readJson(response);
      setNotice(action === 'stop' ? 'Se solicitó detener la campaña.' : action === 'pause' ? 'Se solicitó pausar la campaña.' : 'Campaña reanudada.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo controlar la campaña.');
    } finally {
      setBusy(false);
    }
  };

  const labelCampaign = async (campaignId: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(`/api/lab/campaigns/${encodeURIComponent(campaignId)}/label`, {
        method: 'POST',
        credentials: 'same-origin',
      });
      const data = await readJson(response);
      setNotice(`Etiquetado auditado: ${data.labeled} eventos nuevos; ${data.already_labeled} ya estaban etiquetados.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo aplicar el manifiesto.');
    } finally {
      setBusy(false);
    }
  };

  const card = 'rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl space-y-4';
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-white">Laboratorio experimental Centinela V4</h2>
          <p className="mt-1 text-xs text-slate-400">Sesiones variables reproducibles, campañas HTTP y recolección automática por fases.</p>
        </div>
        <Pill tone={connected ? 'good' : 'warning'}>{connected ? 'Socket conectado' : 'Conexión en recuperación'}</Pill>
      </div>

      {error && <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-300">{error}</div>}
      {notice && <div role="status" className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">{notice}</div>}

      {!snapshot?.experiment_id && (
        <div className={card}>
          <h3 className="text-sm font-bold text-white">Crear experimento Centinela V4</h3>
          <p className="text-xs text-slate-400">Define y preregistra los tres cortes temporales. Las fechas se guardarán en UTC; el horario de los campos corresponde al navegador.</p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="space-y-1 text-xs text-slate-300">
              <span className="font-semibold">Nombre del protocolo</span>
              <input value={protocolName} onChange={(event) => setProtocolName(event.target.value)} maxLength={120} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"/>
            </label>
            <label className="space-y-1 text-xs text-slate-300">
              <span className="font-semibold">Escenario</span>
              <input value={scenario} onChange={(event) => setScenario(event.target.value)} maxLength={120} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"/>
            </label>
            <label className="space-y-1 text-xs text-slate-300">
              <span className="font-semibold">Fin de entrenamiento</span>
              <input type="datetime-local" value={trainEndAt} onChange={(event) => setTrainEndAt(event.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"/>
            </label>
            <label className="space-y-1 text-xs text-slate-300">
              <span className="font-semibold">Fin de validación</span>
              <input type="datetime-local" value={validationEndAt} onChange={(event) => setValidationEndAt(event.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"/>
            </label>
            <label className="space-y-1 text-xs text-slate-300 md:col-span-2">
              <span className="font-semibold">Fin del test y cierre de captura</span>
              <input type="datetime-local" value={testEndAt} onChange={(event) => setTestEndAt(event.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"/>
            </label>
          </div>
          <label className="block space-y-1 text-xs text-slate-300">
            <span className="font-semibold">Descripción y alcance</span>
            <textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={2} maxLength={1000} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"/>
          </label>
          <p className="text-[11px] text-amber-300">Fechas iniciales V4: entrenamiento 1 dic., validación 8 dic. y test 15 dic. de 2026, a las 17:00 (hora de Perú). Verifica que sean futuras antes de crear; después no se deben mover.</p>
          <button type="button" onClick={() => void createExperiment()} disabled={busy || !protocolName.trim() || !scenario.trim()} className="rounded-xl bg-cyan-600 px-4 py-3 text-xs font-bold text-white hover:bg-cyan-500 disabled:opacity-40">
            {busy ? 'Creando…' : 'Crear protocolo y habilitar laboratorio'}
          </button>
        </div>
      )}

      {snapshot?.experiment && (
        <div className={card}>
          <h3 className="text-sm font-bold text-white">Fases temporales preregistradas</h3>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
              <p className="text-[10px] uppercase text-slate-500">Entrenamiento</p>
              <p className="mt-1 text-xs text-white">{localDate(snapshot.experiment.trainEndMs)}</p>
              <Pill tone={snapshot.experiment.trainingFrozen ? 'good' : 'warning'}>{snapshot.experiment.trainingFrozen ? 'Baseline congelado' : 'Solo benignos'}</Pill>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
              <p className="text-[10px] uppercase text-slate-500">Validación</p>
              <p className="mt-1 text-xs text-white">{localDate(snapshot.experiment.validationEndMs)}</p>
              <Pill tone={snapshot.experiment.validationFrozen ? 'good' : 'warning'}>{snapshot.experiment.validationFrozen ? 'Configuración congelada' : 'Pendiente de congelación'}</Pill>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
              <p className="text-[10px] uppercase text-slate-500">Test independiente</p>
              <p className="mt-1 text-xs text-white">{snapshot.experiment.testEndMs ? localDate(snapshot.experiment.testEndMs) : 'Sin corte final preregistrado'}</p>
              <Pill tone={snapshot.experiment.validationFrozen ? 'good' : 'bad'}>{snapshot.experiment.validationFrozen ? 'Preparado' : 'Bloqueado'}</Pill>
            </div>
          </div>
          {snapshot.experiment.testEndMs !== null &&
            Date.now() >= snapshot.experiment.testEndMs &&
            snapshot.campaigns.every((campaign) => !['queued', 'running', 'paused'].includes(campaign.status)) && (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-3">
              <p className="text-[11px] text-slate-400">El corte final fue alcanzado y no hay campañas pendientes. Finaliza el experimento para habilitar la creación del siguiente protocolo.</p>
              <button type="button" disabled={busy} onClick={() => void finishExperiment()} className="rounded-xl bg-cyan-600 px-4 py-3 text-xs font-bold text-white hover:bg-cyan-500 disabled:opacity-40">Finalizar experimento</button>
            </div>
          )}
          {Date.now() >= snapshot.experiment.validationEndMs && snapshot.experiment.trainingFrozen && !snapshot.experiment.validationFrozen && (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-[11px] text-amber-300">Revisa las métricas y etiquetas de validación. Al congelar, el sistema registrará el código y versión de configuración antes de permitir campañas de test.</p>
              <button type="button" disabled={busy} onClick={() => void freezeValidation()} className="rounded-xl bg-amber-600 px-4 py-3 text-xs font-bold text-white hover:bg-amber-500 disabled:opacity-40">Congelar configuración de validación</button>
            </div>
          )}
        </div>
      )}


      {snapshot?.experiment && (
        <div className={card}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white">Recolección científica automática</h3>
              <p className="mt-1 text-xs text-slate-400">El planificador crea lotes de hasta cinco sesiones, rota las cuentas de laboratorio, distribuye horarios y espera a que cada campaña termine antes de continuar.</p>
            </div>
            <Pill tone={snapshot.automation?.enabled ? 'good' : snapshot.automation?.status === 'completed' ? 'good' : 'warning'}>
              {snapshot.automation?.enabled ? 'Automatización activa' : snapshot.automation?.status === 'completed' ? 'Objetivos completados' : 'Automatización detenida'}
            </Pill>
          </div>
          <p className="text-xs text-slate-300">Protocolo actual: V{snapshot.protocol_revision ?? '—'}. Entrenamiento: 200 sesiones benignas; validación: 100 benignas y 30 por escenario de ataque; prueba final: 200 benignas y 50 rápidas, 50 de baja frecuencia y 30 distribuidas.</p>
          {snapshot.automation?.lastError && <p role="status" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">{snapshot.automation.lastError}</p>}
          <div className="flex flex-wrap gap-2">
            <button type="button" disabled={busy || snapshot.protocol_revision !== 4 || snapshot.automation?.enabled === true} onClick={() => void startAutomation()} className="rounded-xl bg-cyan-600 px-4 py-3 text-xs font-bold text-white hover:bg-cyan-500 disabled:opacity-40">Iniciar recolección automática V4</button>
            <button type="button" disabled={busy || snapshot.automation?.enabled !== true} onClick={() => void stopAutomation()} className="rounded-xl border border-rose-500/30 px-4 py-3 text-xs font-bold text-rose-300 disabled:opacity-40">Pausar planificación</button>
          </div>
          {snapshot.protocol_revision !== 4 && <p className="text-[11px] text-amber-300">El experimento V3 activo no se modificará. Finalízalo o ciérralo formalmente y crea un protocolo V4 para habilitar este planificador.</p>}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Agentes activos</p>
          <p className="mt-1 text-2xl font-bold text-white tabular-nums">{activeAgents.length}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">IP verificadas</p>
          <p className="mt-1 text-2xl font-bold text-white tabular-nums">{distinctOrigins}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Campañas registradas</p>
          <p className="mt-1 text-2xl font-bold text-white tabular-nums">{snapshot?.campaigns.length ?? 0}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Eventos en vivo</p>
          <p className="mt-1 text-2xl font-bold text-white tabular-nums">{liveEvents.length}</p>
        </div>
      </div>

      <div className={card}>
        <div>
          <h3 className="text-sm font-bold text-white">Agentes y orígenes de red</h3>
          <p className="mt-1 text-xs text-slate-400">Cada IP se observa en la conexión de registro al coordinador y se muestra solo como prefijo HMAC. Varios agentes detrás de la misma NAT cuentan como un único origen.</p>
        </div>
        {(snapshot?.agents.length ?? 0) === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 p-5 text-sm text-slate-400">No hay agentes registrados. Cada runner externo debe configurarse con el ID, el token y las credenciales del testbed.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-left text-xs">
              <thead className="text-slate-500"><tr><th className="py-2">Agente</th><th>Origen HMAC</th><th>Estado</th><th>Último contacto</th><th>Tarea</th></tr></thead>
              <tbody className="divide-y divide-slate-800">
                {snapshot?.agents.map((agent) => (
                  <tr key={agent.agent_id}>
                    <td className="py-3 text-white font-semibold">{agent.agent_id}</td>
                    <td className="font-mono text-slate-400">{agent.egress_ip_hash_prefix}</td>
                    <td><Pill tone={agent.status === 'ready' || agent.status === 'running' ? 'good' : agent.status === 'offline' ? 'neutral' : 'warning'}>{agent.status}</Pill></td>
                    <td className="text-slate-400">{localDate(agent.last_seen_at)}</td>
                    <td className="font-mono text-slate-500">{agent.current_job_id?.slice(0, 8) || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className={card}>
        <div>
          <h3 className="text-sm font-bold text-white">Configurar campaña experimental</h3>
          <p className="mt-1 text-xs text-slate-400">Las contraseñas no llegan al detector ni se guardan en los eventos. Las tareas de ataque usan un valor inválido fijo; las benignas utilizan las credenciales de las cuentas de laboratorio.</p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <label className="space-y-1 text-xs text-slate-300">
            <span className="font-semibold">Cuenta objetivo</span>
            <select value={targetAccount} onChange={(event) => setTargetAccount(event.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white">
              <option value="ronan">ronan</option><option value="andy">andy</option><option value="stefano">stefano</option>
            </select>
          </label>
          <label className="space-y-1 text-xs text-slate-300">
            <span className="font-semibold">Repeticiones por escenario (1–5)</span>
            <input type="number" min={1} max={5} value={repetitions} onChange={(event) => setRepetitions(Math.max(1, Math.min(5, Number(event.target.value) || 1)))} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"/>
          </label>
          <div className="space-y-1 text-xs text-slate-300">
            <span className="font-semibold">Experimento activo</span>
            <div className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-400">{snapshot?.experiment_id || 'No disponible'}</div>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {(snapshot?.scenarios ?? []).map((scenario) => (
            <label key={scenario.scenario_id} className="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-800 bg-slate-950 p-3">
              <input type="checkbox" checked={selected.includes(scenario.scenario_id)} onChange={() => toggleScenario(scenario.scenario_id)} className="mt-1"/>
              <span className="min-w-0"><strong className="block text-xs text-white">{scenario.label}</strong><span className="mt-1 block text-[11px] text-slate-400">{scenario.description}</span><span className="mt-1 block text-[10px] text-slate-500">Agentes requeridos: {scenario.required_agents}</span></span>
            </label>
          ))}
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="max-w-2xl text-[11px] text-amber-300">El escenario distribuido solo se habilitará cuando existan cuatro IP de salida distintas, verificadas por el servidor. No se aceptan cabeceras que simulen direcciones.</p>
          <button
            type="button"
            onClick={() => void createCampaign()}
            disabled={
              busy ||
              selected.length === 0 ||
              !snapshot?.agent_token_configured ||
              !snapshot?.experiment_id ||
              (snapshot.experiment?.trainingFrozen !== true && snapshot.experiment?.trainEndMs !== undefined && Date.now() >= snapshot.experiment.trainEndMs) ||
              (Date.now() < (snapshot?.experiment?.trainEndMs ?? 0) && selected.some((scenarioId) => scenarioId !== 'benign_mixed')) ||
              (Date.now() >= (snapshot?.experiment?.validationEndMs ?? Infinity) && snapshot?.experiment?.validationFrozen !== true)
            }
            className="rounded-xl bg-cyan-600 px-4 py-3 text-xs font-bold text-white hover:bg-cyan-500 disabled:opacity-40"
          >
            {busy ? 'Procesando…' : 'Crear campaña'}
          </button>
        </div>
      </div>

      <div className={card}>
        <h3 className="text-sm font-bold text-white">Campañas y ejecuciones</h3>
        {(snapshot?.campaigns.length ?? 0) === 0 ? (
          <p className="text-sm text-slate-400">Aún no hay campañas v3 para el experimento activo.</p>
        ) : snapshot?.campaigns.map((campaign) => (
          <div key={campaign.campaign_id} className="rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div><p className="text-xs font-bold text-white">{campaign.campaign_id}</p><p className="mt-1 text-[11px] text-slate-500">Fase: {campaign.phase} · Cuenta: {campaign.target_account} · Repeticiones: {campaign.repetitions}</p></div>
              <div className="flex flex-wrap gap-2 items-center">
                <Pill tone={campaign.status === 'completed' ? 'good' : campaign.status === 'stopped' || campaign.status === 'failed' ? 'bad' : campaign.status === 'paused' ? 'warning' : 'neutral'}>{campaign.status}</Pill>
                <button type="button" disabled={busy || ['completed', 'failed', 'stopped'].includes(campaign.status)} onClick={() => void campaignAction(campaign.campaign_id, campaign.status === 'paused' ? 'resume' : 'pause')} className="rounded-lg border border-slate-700 px-3 py-2 text-[11px] text-slate-200 disabled:opacity-40">{campaign.status === 'paused' ? 'Reanudar' : 'Pausar'}</button>
                <button type="button" disabled={busy || ['completed', 'stopped'].includes(campaign.status)} onClick={() => void campaignAction(campaign.campaign_id, 'stop')} className="rounded-lg border border-rose-500/30 px-3 py-2 text-[11px] text-rose-300 disabled:opacity-40">Detener</button>
                <button type="button" disabled={busy || campaign.status !== 'completed'} onClick={() => void labelCampaign(campaign.campaign_id)} className="rounded-lg border border-emerald-500/30 px-3 py-2 text-[11px] text-emerald-300 disabled:opacity-40">Etiquetar desde manifiesto</button>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[660px] text-left text-[11px]">
                <thead className="text-slate-500"><tr><th className="py-2">Escenario</th><th>Agente</th><th>Estado</th><th>Intentos</th><th>Etiqueta del manifiesto</th><th>Inicio programado</th></tr></thead>
                <tbody className="divide-y divide-slate-800">
                  {campaign.jobs.map((job) => (
                    <tr key={job.job_id}>
                      <td className="py-2 text-slate-300">{SCENARIO_LABELS[job.scenario_id]}</td>
                      <td className="font-mono text-slate-500">{job.agent_id || 'Pendiente'}</td>
                      <td><Pill tone={job.status === 'completed' ? 'good' : job.status === 'failed' || job.status === 'cancelled' ? 'bad' : 'neutral'}>{job.status}</Pill></td>
                      <td className="tabular-nums text-slate-300">{job.attempts_completed}/{job.attempts_planned}</td>
                      <td><Pill tone={job.expected_label === 'attack' ? 'bad' : 'good'}>{job.expected_label}</Pill></td>
                      <td className="text-slate-500">{localDate(job.start_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>

      <div className={card}>
        <div className="flex items-center justify-between gap-3"><h3 className="text-sm font-bold text-white">Eventos de autenticación en vivo</h3><Pill tone={connected ? 'good' : 'warning'}>{connected ? 'En directo' : 'Reconectando'}</Pill></div>
        {liveEvents.length === 0 ? <p className="text-xs text-slate-400">Esperando eventos recibidos desde el portal de laboratorio.</p> : (
          <div className="max-h-80 space-y-2 overflow-y-auto">
            {liveEvents.map((event, index) => (
              <div key={event.event_id || index} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[10px] text-slate-500">{localDate((event.timestamp || 0) * 1000)}</span>
                  <div className="flex gap-2"><Pill tone={event.exitoso ? 'good' : 'warning'}>{event.exitoso ? 'Login correcto' : 'Login fallido'}</Pill>{event.alerta_reglas && <Pill tone="warning">Reglas</Pill>}{event.alerta_ml && <Pill tone="bad">ML</Pill>}</div>
                </div>
                <p className="mt-2 text-[11px] text-slate-300">Agente: {event.metadata?.agent_id || '—'} · Escenario: {event.metadata?.scenario_id || '—'} · IP HMAC: {event.ip || '—'} · Cuenta HMAC: {event.usuario || '—'}</p>
                <p className="mt-1 text-[10px] text-slate-500">Evento: {event.event_id || '—'} · Campaña: {event.campaign_id || '—'} · Run: {event.metadata?.run_id || '—'} · Latencia: {event.latency_total_ms?.toFixed?.(4) ?? '—'} ms</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className={card}>
        <h3 className="text-sm font-bold text-white">Registro de agentes</h3>
        {agentLogs.length === 0 ? <p className="text-xs text-slate-400">Sin mensajes de ejecución todavía.</p> : (
          <div className="max-h-52 space-y-1 overflow-y-auto font-mono text-[10px] text-slate-400">
            {agentLogs.map((entry, index) => <p key={index}>[{localDate(entry.timestamp)}] {entry.agent_id}: {entry.message}</p>)}
          </div>
        )}
      </div>
    </div>
  );
}
