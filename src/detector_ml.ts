/**
 * detector_ml.ts — Detector de fuerza bruta basado en comportamiento (Isolation Forest).
 *
 * Extrae 5 características de comportamiento por IP en una ventana de 120s:
 *   1. num_intentos: cantidad de intentos fallidos recientes
 *   2. num_usuarios_distintos: cuántos usuarios probó esa IP
 *   3. intervalo_promedio: tiempo promedio entre intentos consecutivos
 *   4. intervalo_std: desviación estándar del intervalo
 *   5. hora_del_dia: hora (0-23)
 */

export interface VeredictoML {
  alerta: boolean;
  score: number;
  features: number[];
}

interface IntentoIpML {
  timestamp: number;
  usuario: string;
}

// Estructura de árbol de aislamiento (iTree)
interface TreeNode {
  isLeaf: boolean;
  size?: number;
  splitFeature?: number;
  splitValue?: number;
  left?: TreeNode;
  right?: TreeNode;
}

function cFactor(n: number): number {
  if (n <= 1) return 1;
  if (n === 2) return 1;
  const eulerMascheroni = 0.5772156649;
  return 2 * (Math.log(n - 1) + eulerMascheroni) - (2 * (n - 1)) / n;
}

class IsolationTree {
  public root: TreeNode;

  constructor(data: number[][], currentHeight: number, maxHeight: number) {
    this.root = this.buildTree(data, currentHeight, maxHeight);
  }

  private buildTree(data: number[][], currentHeight: number, maxHeight: number): TreeNode {
    const n = data.length;
    if (currentHeight >= maxHeight || n <= 1) {
      return { isLeaf: true, size: n };
    }

    const numFeatures = data[0].length;
    // Seleccionar una característica aleatoria
    const featureIdx = Math.floor(Math.random() * numFeatures);

    let min = Infinity;
    let max = -Infinity;
    for (let i = 0; i < n; i++) {
      const val = data[i][featureIdx];
      if (val < min) min = val;
      if (val > max) max = val;
    }

    if (min === max) {
      return { isLeaf: true, size: n };
    }

    // Split aleatorio uniforme entre min y max
    const splitValue = min + Math.random() * (max - min);

    const leftData: number[][] = [];
    const rightData: number[][] = [];
    for (let i = 0; i < n; i++) {
      if (data[i][featureIdx] < splitValue) {
        leftData.push(data[i]);
      } else {
        rightData.push(data[i]);
      }
    }

    return {
      isLeaf: false,
      splitFeature: featureIdx,
      splitValue,
      left: this.buildTree(leftData, currentHeight + 1, maxHeight),
      right: this.buildTree(rightData, currentHeight + 1, maxHeight),
    };
  }

  public pathLength(x: number[], node: TreeNode, currentDepth: number): number {
    if (node.isLeaf) {
      const size = node.size || 1;
      return currentDepth + cFactor(size);
    }
    if (node.splitFeature === undefined || node.splitValue === undefined) {
      return currentDepth;
    }
    if (x[node.splitFeature] < node.splitValue) {
      return node.left ? this.pathLength(x, node.left, currentDepth + 1) : currentDepth;
    } else {
      return node.right ? this.pathLength(x, node.right, currentDepth + 1) : currentDepth;
    }
  }
}

class IsolationForestModel {
  private trees: IsolationTree[] = [];
  private threshold = 0.58;
  private subSampleSize = 128;
  private sampleCount = 0;

  constructor(private nEstimators = 100, private contamination = 0.15) {}

  public fit(X: number[][]): void {
    if (X.length === 0) return;
    this.sampleCount = X.length;
    const n = Math.min(X.length, this.subSampleSize);
    const maxHeight = Math.ceil(Math.log2(Math.max(n, 2)));

    this.trees = [];
    for (let i = 0; i < this.nEstimators; i++) {
      // Subsampling aleatorio
      const subSample: number[][] = [];
      for (let j = 0; j < n; j++) {
        const idx = Math.floor(Math.random() * X.length);
        subSample.push(X[idx]);
      }
      this.trees.push(new IsolationTree(subSample, 0, maxHeight));
    }

    // Calcular umbral de acuerdo a contamination
    const scores = X.map((x) => this.rawAnomalyScore(x, n));
    scores.sort((a, b) => a - b);
    const thresholdIdx = Math.floor((1 - this.contamination) * scores.length);
    this.threshold = scores[Math.min(thresholdIdx, scores.length - 1)] || 0.58;
  }

  private rawAnomalyScore(x: number[], n: number): number {
    if (this.trees.length === 0) return 0.5;
    let totalPath = 0;
    for (const tree of this.trees) {
      totalPath += tree.pathLength(x, tree.root, 0);
    }
    const avgPath = totalPath / this.trees.length;
    const c = cFactor(n);
    return Math.pow(2, -avgPath / c);
  }

  public scoreSample(x: number[]): { score: number; isAnomaly: boolean } {
    const n = Math.min(this.sampleCount || 128, this.subSampleSize);
    const score = this.rawAnomalyScore(x, n);
    // score_ml en sklearn decision_function es típicamente negativo cuando hay anomalía
    // y positivo cuando es normal: offset de 0.5
    const normalizedScore = Math.round((0.5 - score) * 10000) / 10000;
    const isAnomaly = score >= this.threshold;
    return {
      score: normalizedScore,
      isAnomaly,
    };
  }
}

export class DetectorML {
  private ventanaFeatures: number;
  private contamination: number;
  private modelo: IsolationForestModel | null = null;
  public entrenado = false;
  private intentosPorIp: Map<string, IntentoIpML[]> = new Map();

  constructor(ventanaFeatures = 120, contamination = 0.15) {
    this.ventanaFeatures = ventanaFeatures;
    this.contamination = contamination;
  }

  private limpiar(cola: IntentoIpML[], ahora: number): IntentoIpML[] {
    const lim = ahora - this.ventanaFeatures;
    return cola.filter((item) => item.timestamp >= lim);
  }

  private extraerFeatures(ip: string, ahora: number): number[] {
    let cola = this.intentosPorIp.get(ip) || [];
    cola = this.limpiar(cola, ahora);
    this.intentosPorIp.set(ip, cola);

    const timestamps = cola.map((i) => i.timestamp);
    const usuarios = new Set(cola.map((i) => i.usuario));

    const numIntentos = timestamps.length;
    const numUsuarios = usuarios.size;

    let intervaloPromedio = this.ventanaFeatures;
    let intervaloStd = 0.0;

    if (numIntentos >= 2) {
      const sortedTs = [...timestamps].sort((a, b) => a - b);
      const diffs: number[] = [];
      for (let i = 1; i < sortedTs.length; i++) {
        diffs.push(sortedTs[i] - sortedTs[i - 1]);
      }
      const sum = diffs.reduce((a, b) => a + b, 0);
      intervaloPromedio = sum / diffs.length;
      const variance = diffs.reduce((a, b) => a + Math.pow(b - intervaloPromedio, 2), 0) / diffs.length;
      intervaloStd = Math.sqrt(variance);
    }

    const hora = new Date(ahora * 1000).getHours();

    return [
      numIntentos,
      numUsuarios,
      Math.round(intervaloPromedio * 100) / 100,
      Math.round(intervaloStd * 100) / 100,
      hora,
    ];
  }

  public entrenarConDatosNormales(muestrasNormales: number[][]): void {
    const model = new IsolationForestModel(120, this.contamination);
    model.fit(muestrasNormales);
    this.modelo = model;
    this.entrenado = true;
  }

  public registrarYEvaluar(ip: string, usuario: string, exitoso: boolean, timestamp?: number): VeredictoML {
    const ahora = timestamp ?? Date.now() / 1000;

    if (!exitoso) {
      const cola = this.intentosPorIp.get(ip) || [];
      cola.push({ timestamp: ahora, usuario });
      this.intentosPorIp.set(ip, cola);
    }

    const features = this.extraerFeatures(ip, ahora);

    if (!this.entrenado || !this.modelo) {
      return { alerta: false, score: 0.0, features };
    }

    const { score, isAnomaly } = this.modelo.scoreSample(features);
    return {
      alerta: isAnomaly,
      score,
      features,
    };
  }

  public reset(): void {
    this.intentosPorIp.clear();
  }
}

export function generarMuestrasNormales(n = 300): number[][] {
  const muestras: number[][] = [];
  for (let i = 0; i < n; i++) {
    // Los humanos normalmente fallan entre 0 y 2 veces en 120s
    const numIntentos = Math.random() < 0.6 ? 0 : Math.random() < 0.85 ? 1 : 2;
    const numUsuarios = numIntentos > 0 ? 1 : 0;

    let intervaloProm = 120;
    let intervaloStd = 0.0;

    if (numIntentos >= 2) {
      intervaloProm = 20 + Math.random() * 80; // 20s a 100s
      intervaloStd = 5 + Math.random() * 35;
    }

    const hora = Math.floor(Math.random() * 24);
    muestras.push([numIntentos, numUsuarios, intervaloProm, intervaloStd, hora]);
  }
  return muestras;
}
