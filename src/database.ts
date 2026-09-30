/**
 * database.ts — Capa de persistencia en memoria para intentos e IPs bloqueadas.
 * 
 * Separa:
 *   - es_simulado = 1 -> tráfico generado por botones de simulación o experimentos
 *     (tiene es_ataque_real confiable para calcular precisión, recall, F1)
 *   - es_simulado = 0 -> tráfico real que llegó desde un login externo (/registrar_intento)
 *     (no contamina las métricas experimentales)
 */

export interface Intento {
  id: number;
  timestamp: number;
  ip: string;
  usuario: string;
  exitoso: boolean;
  es_ataque_real: number;
  alerta_reglas: number;
  alerta_ml: number;
  origen: string;
  es_simulado: number;
}

export interface IpBloqueada {
  ip: string;
  hasta: number;
  creada_en: number;
}

export interface MetricaMetodo {
  verdaderos_positivos: number;
  falsos_negativos: number;
  falsos_positivos: number;
  verdaderos_negativos: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface MetricasResumen {
  alerta_reglas: MetricaMetodo;
  alerta_ml: MetricaMetodo;
  total_intentos: number;
}

class Database {
  private intentos: Intento[] = [];
  private ipBloqueadas: Map<string, IpBloqueada> = new Map();
  private nextId = 1;

  public initDb(): void {
    // Inicialización del almacén en memoria
  }

  public checkConnection(): boolean {
    return true;
  }

  public registrarIntento(
    ip: string,
    usuario: string,
    exitoso: boolean,
    es_ataque_real = 0,
    alerta_reglas = 0,
    alerta_ml = 0,
    origen = 'simulador',
    timestamp?: number,
    es_simulado = 1
  ): number {
    const id = this.nextId++;
    const ts = timestamp ?? Date.now() / 1000;
    const intento: Intento = {
      id,
      timestamp: ts,
      ip,
      usuario,
      exitoso,
      es_ataque_real,
      alerta_reglas,
      alerta_ml,
      origen,
      es_simulado,
    };
    this.intentos.push(intento);
    // Limitar tamaño en memoria para estabilidad
    if (this.intentos.length > 5000) {
      this.intentos.splice(0, 1000);
    }
    return id;
  }

  public obtenerIntentosRecientes(limite = 200, soloProduccion = false): Intento[] {
    let list = this.intentos;
    if (soloProduccion) {
      list = list.filter((i) => i.es_simulado === 0);
    }
    return list.slice(-limite).reverse();
  }

  public limpiar(): void {
    this.intentos = [];
  }

  public metricasResumen(): MetricasResumen | null {
    const simulados = this.intentos.filter((i) => i.es_simulado === 1);
    if (simulados.length === 0) return null;

    const calcular = (campo: 'alerta_reglas' | 'alerta_ml'): MetricaMetodo => {
      let vp = 0, fn = 0, fp = 0, vn = 0;
      for (const i of simulados) {
        const predicho = i[campo] === 1;
        const real = i.es_ataque_real === 1;
        if (real && predicho) vp++;
        else if (real && !predicho) fn++;
        else if (!real && predicho) fp++;
        else vn++;
      }
      const precision = vp + fp > 0 ? vp / (vp + fp) : 0;
      const recall = vp + fn > 0 ? vp / (vp + fn) : 0;
      const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

      return {
        verdaderos_positivos: vp,
        falsos_negativos: fn,
        falsos_positivos: fp,
        verdaderos_negativos: vn,
        precision: Math.round(precision * 1000) / 1000,
        recall: Math.round(recall * 1000) / 1000,
        f1: Math.round(f1 * 1000) / 1000,
      };
    };

    return {
      alerta_reglas: calcular('alerta_reglas'),
      alerta_ml: calcular('alerta_ml'),
      total_intentos: simulados.length,
    };
  }

  public contadorProduccion(): { total: number; alertas: number } {
    const prod = this.intentos.filter((i) => i.es_simulado === 0);
    const alertas = prod.filter((i) => i.alerta_reglas === 1 || i.alerta_ml === 1).length;
    return {
      total: prod.length,
      alertas,
    };
  }

  private purgarExpiradas(): void {
    const ahora = Date.now() / 1000;
    for (const [ip, b] of this.ipBloqueadas.entries()) {
      if (b.hasta <= ahora) {
        this.ipBloqueadas.delete(ip);
      }
    }
  }

  public ipEstaBloqueada(ip: string): [boolean, number] {
    this.purgarExpiradas();
    const b = this.ipBloqueadas.get(ip);
    if (!b) return [false, 0];
    const ahora = Date.now() / 1000;
    const restante = Math.ceil(b.hasta - ahora);
    if (restante <= 0) {
      this.ipBloqueadas.delete(ip);
      return [false, 0];
    }
    return [true, restante];
  }

  public bloquearIp(ip: string, segundos: number): number {
    const ahora = Date.now() / 1000;
    const hasta = ahora + segundos;
    this.ipBloqueadas.set(ip, {
      ip,
      hasta,
      creada_en: ahora,
    });
    return hasta;
  }

  public listarIpsBloqueadas(): Record<string, number> {
    this.purgarExpiradas();
    const ahora = Date.now() / 1000;
    const res: Record<string, number> = {};
    for (const [ip, b] of this.ipBloqueadas.entries()) {
      const rem = Math.ceil(b.hasta - ahora);
      if (rem > 0) {
        res[ip] = rem;
      }
    }
    return res;
  }

  public limpiarBloqueos(): void {
    this.ipBloqueadas.clear();
  }
}

export const db = new Database();
