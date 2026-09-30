/**
 * detector_reglas.ts — Detector de fuerza bruta basado en reglas adaptativas.
 * 
 * Regla 1: Ráfaga rápida por IP (umbral_rapido en ventana_rapida)
 * Regla 2: Ataque lento (low-and-slow) por IP (umbral_lento en ventana_lenta)
 * Regla 3: Ataque distribuido contra el mismo usuario (umbral_distribuido_ips en ventana_distribuida)
 */

export interface VeredictoReglas {
  alerta: boolean;
  razon: string | null;
}

interface IntentoIp {
  timestamp: number;
  usuario: string;
}

interface IntentoUsuario {
  timestamp: number;
  ip: string;
}

export class DetectorReglas {
  private umbralRapido: number;
  private ventanaRapida: number;
  private umbralLento: number;
  private ventanaLenta: number;
  private umbralDistribuidoIps: number;
  private ventanaDistribuida: number;

  private intentosPorIp: Map<string, IntentoIp[]> = new Map();
  private intentosPorUsuario: Map<string, IntentoUsuario[]> = new Map();

  constructor(
    umbralRapido = 5,
    ventanaRapida = 60,
    umbralLento = 8,
    ventanaLenta = 900,
    umbralDistribuidoIps = 4,
    ventanaDistribuida = 120
  ) {
    this.umbralRapido = umbralRapido;
    this.ventanaRapida = ventanaRapida;
    this.umbralLento = umbralLento;
    this.ventanaLenta = ventanaLenta;
    this.umbralDistribuidoIps = umbralDistribuidoIps;
    this.ventanaDistribuida = ventanaDistribuida;
  }

  private limpiarVentana<T extends { timestamp: number }>(cola: T[], ahora: number, ventana: number): T[] {
    const lim = ahora - ventana;
    return cola.filter((item) => item.timestamp >= lim);
  }

  public evaluar(ip: string, usuario: string, exitoso: boolean, timestamp?: number): VeredictoReglas {
    const ahora = timestamp ?? Date.now() / 1000;

    if (exitoso) {
      return { alerta: false, razon: null };
    }

    // Registrar intento fallido
    let colaIp = this.intentosPorIp.get(ip) || [];
    colaIp.push({ timestamp: ahora, usuario });
    colaIp = this.limpiarVentana(colaIp, ahora, this.ventanaLenta);
    this.intentosPorIp.set(ip, colaIp);

    let colaUser = this.intentosPorUsuario.get(usuario) || [];
    colaUser.push({ timestamp: ahora, ip });
    colaUser = this.limpiarVentana(colaUser, ahora, this.ventanaDistribuida);
    this.intentosPorUsuario.set(usuario, colaUser);

    // Regla 1: ráfaga rápida por IP
    const recientesRapidos = colaIp.filter((item) => ahora - item.timestamp <= this.ventanaRapida);
    if (recientesRapidos.length >= this.umbralRapido) {
      return {
        alerta: true,
        razon: `ráfaga rápida: ${recientesRapidos.length} intentos desde ${ip} en ${this.ventanaRapida}s`,
      };
    }

    // Regla 2: ataque lento (low-and-slow) por IP
    if (colaIp.length >= this.umbralLento) {
      return {
        alerta: true,
        razon: `ataque lento: ${colaIp.length} intentos desde ${ip} en ${this.ventanaLenta}s`,
      };
    }

    // Regla 3: ataque distribuido contra el mismo usuario
    const ipsDistintas = new Set(colaUser.map((item) => item.ip));
    if (ipsDistintas.size >= this.umbralDistribuidoIps) {
      return {
        alerta: true,
        razon: `ataque distribuido: ${ipsDistintas.size} IPs distintas probando el usuario '${usuario}' en ${this.ventanaDistribuida}s`,
      };
    }

    return { alerta: false, razon: null };
  }

  public reset(): void {
    this.intentosPorIp.clear();
    this.intentosPorUsuario.clear();
  }
}
