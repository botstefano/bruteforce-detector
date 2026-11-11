import { createHmac } from 'node:crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';

export type GroundTruthLabel = 'unknown' | 'benign' | 'attack';

export interface CapturedAuthEvent {
  event_id: string;
  timestamp: number;
  ip: string;
  usuario: string;
  exitoso: boolean;
  origen: string;
  es_simulado: boolean;
  alerta_reglas: boolean;
  razon_reglas: string | null;
  alerta_ml: boolean;
  score_ml: number;
  modelos_ml: {
    isolation_forest: { alerta: boolean };
    one_class_svm: { alerta: boolean };
    lof: { alerta: boolean };
  };
  latency_rules_ms: number;
  latency_ml_ms: number;
  latency_total_ms: number;
}

export interface CapturedEventRow {
  event_id: string;
  occurred_at: string;
  received_at: string;
  source_ip_hash: string;
  user_key_hash: string;
  auth_success: boolean;
  origin: string;
  is_simulated: boolean;
  ground_truth_label: GroundTruthLabel;
  ground_truth_method: string | null;
  ground_truth_updated_at: string | null;
  ground_truth_notes: string | null;
  experiment_id: string | null;
  scenario: string | null;
  request_id: string | null;
  alerta_reglas: boolean;
  razon_reglas: string | null;
  alerta_ml: boolean;
  alerta_iforest: boolean;
  alerta_ocsvm: boolean;
  alerta_lof: boolean;
  score_ml: number;
  latency_rules_ms: number;
  latency_ml_ms: number;
  latency_total_ms: number;
  detector_version: string;
  config_version: string;
  metadata: Record<string, unknown>;
}

const supabaseUrl = process.env.SUPABASE_URL?.trim() ?? '';
const supabaseKey =
  process.env.SUPABASE_SECRET_KEY?.trim() ||
  process.env.SUPABASE_SERVICE_ROLE_KEY?.trim() ||
  '';
const hashSecret = process.env.CENTINELA_HASH_SECRET?.trim() ?? '';

const client: SupabaseClient | null =
  supabaseUrl && supabaseKey
    ? createClient(supabaseUrl, supabaseKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
          detectSessionInUrl: false,
        },
      })
    : null;

export function eventStoreStatus() {
  return {
    configured: Boolean(client && hashSecret),
    clientConfigured: Boolean(client),
    hashSecretConfigured: Boolean(hashSecret),
  };
}

function hashIdentifier(value: string): string {
  if (!hashSecret) {
    throw new Error('CENTINELA_HASH_SECRET no está configurado.');
  }
  return createHmac('sha256', hashSecret).update(value).digest('hex');
}

export async function persistObservedEvent(event: CapturedAuthEvent): Promise<void> {
  if (event.es_simulado) {
    throw new Error('El almacén de captura rechaza eventos marcados como simulados.');
  }
  if (!client) {
    throw new Error('Supabase no está configurado. Define SUPABASE_URL y SUPABASE_SECRET_KEY.');
  }
  if (!hashSecret) {
    throw new Error('Falta CENTINELA_HASH_SECRET para seudonimizar identificadores.');
  }

  const row = {
    event_id: event.event_id,
    occurred_at: new Date(event.timestamp * 1000).toISOString(),
    source_ip_hash: hashIdentifier(event.ip),
    user_key_hash: hashIdentifier(event.usuario.trim().toLowerCase()),
    auth_success: event.exitoso,
    origin: event.origen,
    is_simulated: false,
    ground_truth_label: 'unknown',
    ground_truth_method: null,
    ground_truth_updated_at: null,
    ground_truth_notes: null,
    experiment_id: process.env.CENTINELA_EXPERIMENT_ID?.trim() || null,
    scenario: event.origen,
    request_id: null,
    alerta_reglas: event.alerta_reglas,
    razon_reglas: event.razon_reglas,
    alerta_ml: event.alerta_ml,
    alerta_iforest: event.modelos_ml.isolation_forest.alerta,
    alerta_ocsvm: event.modelos_ml.one_class_svm.alerta,
    alerta_lof: event.modelos_ml.lof.alerta,
    score_ml: event.score_ml,
    latency_rules_ms: event.latency_rules_ms,
    latency_ml_ms: event.latency_ml_ms,
    latency_total_ms: event.latency_total_ms,
    detector_version: process.env.CENTINELA_VERSION?.trim() || 'unversioned',
    config_version: process.env.CENTINELA_CONFIG_VERSION?.trim() || 'unversioned',
    metadata: {},
  };

  const { error } = await client.from('centinela_auth_events').insert(row);
  if (error) {
    throw new Error(`No se pudo persistir el evento en Supabase: ${error.message}`);
  }
}

export async function fetchObservedEvents(): Promise<CapturedEventRow[]> {
  if (!client || !hashSecret) {
    throw new Error('El almacén persistente de Centinela no está configurado.');
  }

  const rows: CapturedEventRow[] = [];
  const pageSize = 1000;
  const maxRows = 100000;

  for (let offset = 0; offset < maxRows; offset += pageSize) {
    const end = Math.min(offset + pageSize - 1, maxRows - 1);
    const { data, error } = await client
      .from('centinela_auth_events')
      .select('*')
      .eq('is_simulated', false)
      .order('occurred_at', { ascending: true })
      .range(offset, end);

    if (error) {
      throw new Error(`No se pudieron consultar los eventos: ${error.message}`);
    }

    const page = (data ?? []) as CapturedEventRow[];
    rows.push(...page);
    if (page.length < pageSize) break;
  }

  if (rows.length >= maxRows) {
    throw new Error(`La exportación alcanzó el límite de seguridad de ${maxRows} eventos; exporta por periodos.`);
  }
  return rows;
}

export async function fetchBenignTrainingSamples(windowSeconds = 120): Promise<number[][]> {
  const events = (await fetchObservedEvents())
    .filter((event) => event.ground_truth_label === 'benign')
    .sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at));

  const historyByIp = new Map<string, Array<{ timestamp: number; user: string }>>();
  const samples: number[][] = [];

  for (const event of events) {
    const timestamp = Date.parse(event.occurred_at) / 1000;
    const queue = (historyByIp.get(event.source_ip_hash) ?? [])
      .filter((item) => item.timestamp >= timestamp - windowSeconds);

    // El detector online incorpora únicamente los intentos fallidos antes de extraer features.
    if (!event.auth_success) {
      queue.push({ timestamp, user: event.user_key_hash });
    }
    historyByIp.set(event.source_ip_hash, queue);

    const timestamps = queue.map((item) => item.timestamp).sort((a, b) => a - b);
    const distinctUsers = new Set(queue.map((item) => item.user)).size;
    let intervalMean = windowSeconds;
    let intervalStd = 0;

    if (timestamps.length >= 2) {
      const intervals = timestamps.slice(1).map((value, index) => value - timestamps[index]);
      intervalMean = intervals.reduce((sum, value) => sum + value, 0) / intervals.length;
      const variance = intervals.reduce((sum, value) => sum + (value - intervalMean) ** 2, 0) / intervals.length;
      intervalStd = Math.sqrt(variance);
    }

    samples.push([
      timestamps.length,
      distinctUsers,
      Math.round(intervalMean * 100) / 100,
      Math.round(intervalStd * 100) / 100,
      new Date(timestamp * 1000).getHours(),
    ]);
  }

  return samples;
}

export async function labelObservedEvent(input: {
  eventId: string;
  label: Exclude<GroundTruthLabel, 'unknown'>;
  method: string;
  rationale: string;
  labeledBy?: string;
}) {
  if (!client || !hashSecret) {
    throw new Error('El almacén persistente de Centinela no está configurado.');
  }
  if (!input.method.trim() || !input.rationale.trim()) {
    throw new Error('El método y la justificación del etiquetado son obligatorios.');
  }

  const { data, error } = await client.rpc('label_centinela_event', {
    p_event_id: input.eventId,
    p_label: input.label,
    p_method: input.method.trim(),
    p_rationale: input.rationale.trim(),
    p_labeled_by: input.labeledBy?.trim() || null,
  });

  if (error) {
    throw new Error(`No se pudo etiquetar el evento de forma transaccional: ${error.message}`);
  }
  return data;
}

function calculateMetrics(
  events: CapturedEventRow[],
  prediction: (event: CapturedEventRow) => boolean
) {
  let tp = 0, fp = 0, fn = 0, tn = 0;

  for (const event of events) {
    const predicted = prediction(event);
    const actual = event.ground_truth_label === 'attack';
    if (actual && predicted) tp++;
    else if (!actual && predicted) fp++;
    else if (actual && !predicted) fn++;
    else tn++;
  }

  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;
  const specificity = fp + tn ? tn / (fp + tn) : 0;
  const accuracy = tp + fp + fn + tn ? (tp + tn) / (tp + fp + fn + tn) : 0;

  return {
    tp, fp, fn, tn,
    precision, recall, f1,
    false_positive_rate: fpr,
    specificity,
    accuracy,
  };
}

export async function calculateObservedMetrics() {
  const all = await fetchObservedEvents();
  const labeled = all.filter((event) => event.ground_truth_label !== 'unknown');
  const benign = labeled.filter((event) => event.ground_truth_label === 'benign').length;
  const attacks = labeled.filter((event) => event.ground_truth_label === 'attack').length;

  const methods = {
    rules: calculateMetrics(labeled, (event) => event.alerta_reglas),
    ml_ensemble: calculateMetrics(labeled, (event) => event.alerta_ml),
    isolation_forest: calculateMetrics(labeled, (event) => event.alerta_iforest),
    one_class_svm: calculateMetrics(labeled, (event) => event.alerta_ocsvm),
    lof: calculateMetrics(labeled, (event) => event.alerta_lof),
  };
  const mean = (values: number[]) => values.length
    ? values.reduce((sum, value) => sum + value, 0) / values.length
    : null;
  const latency = {
    rules_mean_ms: mean(all.map((event) => event.latency_rules_ms).filter(Number.isFinite)),
    ml_mean_ms: mean(all.map((event) => event.latency_ml_ms).filter(Number.isFinite)),
    total_mean_ms: mean(all.map((event) => event.latency_total_ms).filter(Number.isFinite)),
    sample_size: all.length,
  };

  return {
    source: 'centinela_supabase_observed_events',
    total_captured_events: all.length,
    labeled_events: labeled.length,
    unknown_events: all.length - labeled.length,
    benign_events: benign,
    attack_events: attacks,
    metrics: methods,
    latency,
    note: labeled.length === 0
      ? 'No hay eventos etiquetados; no se calculan métricas de clasificación.'
      : 'Las métricas incluyen exclusivamente eventos capturados y etiquetados como benignos o ataques.',
  };
}
