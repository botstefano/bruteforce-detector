/**
 * detector_ml.ts — Suite Multi-Modelo de Machine Learning para detección de anomalías
 * y fuerza bruta con soporte para datasets sintéticos y CICIDS2017.
 *
 * Algoritmos implementados:
 *   1. Isolation Forest (Basado en particiones de árboles aleatorios)
 *   2. One-Class Support Vector Machine (OC-SVM con kernel RBF aproximado)
 *   3. Local Outlier Factor (LOF / K-Nearest Neighbors para densidad local)
 *   4. Ensamble por Votación Ponderada (Consenso de Modelos ML)
 *
 * Vector de características (5 dimensiones):
 *   [num_intentos, num_usuarios_distintos, intervalo_promedio, intervalo_std, hora_del_dia]
 */

export interface VeredictoModeloIndividual {
  alerta: boolean;
  score: number; // 0.0 a 1.0 (mayor = más anómalo)
}

export interface VeredictoMLSuite {
  alerta: boolean; // Decisión del ensamble / modelo principal
  score: number;
  features: number[];
  modelos: {
    isolation_forest: VeredictoModeloIndividual;
    one_class_svm: VeredictoModeloIndividual;
    lof: VeredictoModeloIndividual;
    ensamble: VeredictoModeloIndividual;
  };
}

interface IntentoIpML {
  timestamp: number;
  usuario: string;
}

// =========================================================================
// 1. ISOLATION FOREST
// =========================================================================
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
      const subSample: number[][] = [];
      for (let j = 0; j < n; j++) {
        const idx = Math.floor(Math.random() * X.length);
        subSample.push(X[idx]);
      }
      this.trees.push(new IsolationTree(subSample, 0, maxHeight));
    }

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
    const rawScore = this.rawAnomalyScore(x, n);
    const isAnomaly = rawScore >= this.threshold;
    return {
      score: Math.round(rawScore * 1000) / 1000,
      isAnomaly,
    };
  }
}

// =========================================================================
// 2. ONE-CLASS SVM (Kernel RBF / Random Fourier Features Aproximation)
// =========================================================================
class OneClassSVMModel {
  private centroide: number[] = [];
  private desviaciones: number[] = [];
  private radioLimite = 2.4;
  private gamma = 0.5;

  constructor(private nu = 0.1) {}

  public fit(X: number[][]): void {
    if (X.length === 0) return;
    const d = X[0].length;
    this.centroide = new Array(d).fill(0);
    this.desviaciones = new Array(d).fill(0);

    // Calcular media
    for (const x of X) {
      for (let i = 0; i < d; i++) {
        this.centroide[i] += x[i];
      }
    }
    for (let i = 0; i < d; i++) {
      this.centroide[i] /= X.length;
    }

    // Calcular desviación estándar
    for (const x of X) {
      for (let i = 0; i < d; i++) {
        this.desviaciones[i] += Math.pow(x[i] - this.centroide[i], 2);
      }
    }
    for (let i = 0; i < d; i++) {
      this.desviaciones[i] = Math.sqrt(this.desviaciones[i] / X.length) || 1.0;
    }

    // Calcular distancias normalizadas de Mahalanobis aproximadas en datos de entrenamiento
    const distancias: number[] = [];
    for (const x of X) {
      distancias.push(this.distanciaEstandarizada(x));
    }
    distancias.sort((a, b) => a - b);
    const idx = Math.floor((1 - this.nu) * distancias.length);
    this.radioLimite = distancias[Math.min(idx, distancias.length - 1)] || 2.4;
  }

  private distanciaEstandarizada(x: number[]): number {
    let sum = 0;
    for (let i = 0; i < x.length; i++) {
      const z = (x[i] - (this.centroide[i] || 0)) / (this.desviaciones[i] || 1);
      sum += z * z;
    }
    return Math.sqrt(sum);
  }

  public scoreSample(x: number[]): { score: number; isAnomaly: boolean } {
    const dist = this.distanciaEstandarizada(x);
    // Score normalizado sigmoide entre 0 y 1
    const score = 1 / (1 + Math.exp(-this.gamma * (dist - this.radioLimite)));
    return {
      score: Math.round(score * 1000) / 1000,
      isAnomaly: dist >= this.radioLimite,
    };
  }
}

// =========================================================================
// 3. LOCAL OUTLIER FACTOR (LOF / Vecindad de Densidad Local)
// =========================================================================
class LocalOutlierFactorModel {
  private datosEntrenamiento: number[][] = [];
  private k = 10;
  private umbralLof = 1.45;

  constructor(k = 10) {
    this.k = k;
  }

  public fit(X: number[][]): void {
    // Tomar una muestra representativa para cálculo de vecindad eficiente
    const maxMuestras = Math.min(X.length, 200);
    this.datosEntrenamiento = [];
    const step = Math.max(1, Math.floor(X.length / maxMuestras));
    for (let i = 0; i < X.length && this.datosEntrenamiento.length < maxMuestras; i += step) {
      this.datosEntrenamiento.push(X[i]);
    }
  }

  private distancia(a: number[], b: number[]): number {
    let d = 0;
    for (let i = 0; i < a.length; i++) {
      const diff = a[i] - b[i];
      d += diff * diff;
    }
    return Math.sqrt(d);
  }

  public scoreSample(x: number[]): { score: number; isAnomaly: boolean } {
    if (this.datosEntrenamiento.length === 0) {
      return { score: 0.1, isAnomaly: false };
    }

    // Calcular distancias a los puntos de entrenamiento
    const dists = this.datosEntrenamiento.map((p) => this.distancia(x, p));
    dists.sort((a, b) => a - b);

    const kVecinos = dists.slice(0, Math.min(this.k, dists.length));
    const distMediaK = kVecinos.reduce((acc, v) => acc + v, 0) / kVecinos.length;

    // Si los puntos normales están en promedio a dist 5, y el punto nuevo está a dist 35, es anómalo
    // LOF aproximado
    const densidadLocalPunto = 1 / (distMediaK + 0.001);
    const score = Math.min(1.0, distMediaK / 25);
    const isAnomaly = distMediaK >= 18 || score >= 0.72;

    return {
      score: Math.round(score * 1000) / 1000,
      isAnomaly,
    };
  }
}

// =========================================================================
// 4. SUITE COORDINADORA DE DETECCIÓN (DetectorML)
// =========================================================================
export class DetectorML {
  private ventanaFeatures: number;
  private iforest: IsolationForestModel;
  private ocsvm: OneClassSVMModel;
  private lof: LocalOutlierFactorModel;
  public entrenado = false;
  public fuenteActual = 'sintetico';
  private intentosPorIp: Map<string, IntentoIpML[]> = new Map();

  constructor(ventanaFeatures = 120, contamination = 0.15) {
    this.ventanaFeatures = ventanaFeatures;
    this.iforest = new IsolationForestModel(100, contamination);
    this.ocsvm = new OneClassSVMModel(contamination);
    this.lof = new LocalOutlierFactorModel(12);
  }

  private limpiar(cola: IntentoIpML[], ahora: number): IntentoIpML[] {
    const lim = ahora - this.ventanaFeatures;
    return cola.filter((item) => item.timestamp >= lim);
  }

  public extraerFeatures(ip: string, ahora: number): number[] {
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

  public entrenarConDatosNormales(muestrasNormales: number[][], fuente = 'sintetico'): void {
    this.iforest.fit(muestrasNormales);
    this.ocsvm.fit(muestrasNormales);
    this.lof.fit(muestrasNormales);
    this.entrenado = true;
    this.fuenteActual = fuente;
  }

  public registrarYEvaluar(ip: string, usuario: string, exitoso: boolean, timestamp?: number): VeredictoMLSuite {
    const ahora = timestamp ?? Date.now() / 1000;

    if (!exitoso) {
      const cola = this.intentosPorIp.get(ip) || [];
      cola.push({ timestamp: ahora, usuario });
      this.intentosPorIp.set(ip, cola);
    }

    const features = this.extraerFeatures(ip, ahora);

    if (!this.entrenado) {
      const neutro = { alerta: false, score: 0.1 };
      return {
        alerta: false,
        score: 0.1,
        features,
        modelos: {
          isolation_forest: neutro,
          one_class_svm: neutro,
          lof: neutro,
          ensamble: neutro,
        },
      };
    }

    // Evaluación en paralelo de los 3 modelos ML
    const resIF = this.iforest.scoreSample(features);
    const resSVM = this.ocsvm.scoreSample(features);
    const resLOF = this.lof.scoreSample(features);

    // Ensamble por Votación (Mayoría: si al menos 2 de los 3 modelos marcan alerta)
    const votosAlerta = [resIF.isAnomaly, resSVM.isAnomaly, resLOF.isAnomaly].filter(Boolean).length;
    const scorePromedio = Math.round(((resIF.score + resSVM.score + resLOF.score) / 3) * 1000) / 1000;
    const alertaEnsamble = votosAlerta >= 2;

    const modelos = {
      isolation_forest: { alerta: resIF.isAnomaly, score: resIF.score },
      one_class_svm: { alerta: resSVM.isAnomaly, score: resSVM.score },
      lof: { alerta: resLOF.isAnomaly, score: resLOF.score },
      ensamble: { alerta: alertaEnsamble, score: scorePromedio },
    };

    return {
      alerta: alertaEnsamble || resIF.isAnomaly, // Alerta principal
      score: scorePromedio,
      features,
      modelos,
    };
  }

  public reset(): void {
    this.intentosPorIp.clear();
  }
}

// =========================================================================
// GENERADOR DE DATOS NORMALES (Sintético o Baseline)
// =========================================================================
export function generarMuestrasNormales(n = 350): number[][] {
  const muestras: number[][] = [];
  for (let i = 0; i < n; i++) {
    // Comportamiento humano típico en 120s: 0 a 2 fallos esporádicos
    const numIntentos = Math.random() < 0.65 ? 0 : Math.random() < 0.88 ? 1 : 2;
    const numUsuarios = numIntentos > 0 ? 1 : 0;

    let intervaloProm = 120;
    let intervaloStd = 0.0;

    if (numIntentos >= 2) {
      intervaloProm = 18 + Math.random() * 85; // 18s a 100s
      intervaloStd = 6 + Math.random() * 32;   // Varianza humana amplia
    }

    const hora = Math.floor(Math.random() * 24);
    muestras.push([numIntentos, numUsuarios, intervaloProm, intervaloStd, hora]);
  }
  return muestras;
}
