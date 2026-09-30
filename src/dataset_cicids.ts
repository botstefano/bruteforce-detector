// Dataset sintético generado basado en las distribuciones estadísticas de flujos benignos de CICIDS2017
// Características: [num_intentos, num_usuarios, intervalo_promedio_seg, intervalo_std, hora]
export function generarDatasetCicids2017(n = 500): number[][] {
  const muestras: number[][] = [];
  for (let i = 0; i < n; i++) {
    // En CICIDS2017 los flujos web BENIGN tienen conexiones muy espaciadas y sesiones únicas
    const numIntentos = Math.random() < 0.75 ? 0 : Math.random() < 0.92 ? 1 : 2;
    const numUsuarios = numIntentos > 0 ? 1 : 0;
    
    // Intervalos inter-arribo típicos de usuarios humanos reales navegando (distribución gamma/exponencial)
    let intervaloProm = 120.0;
    let intervaloStd = 0.0;

    if (numIntentos >= 2) {
      intervaloProm = 25.0 + Math.random() * 85.0; // 25s a 110s
      intervaloStd = 8.0 + Math.random() * 40.0;   // Alta varianza natural
    }

    // Distribución horaria realista de oficina (pico 9:00 a 18:00)
    let hora = Math.floor(Math.random() * 24);
    if (Math.random() < 0.7) {
      hora = 8 + Math.floor(Math.random() * 11); // Horario laboral
    }

    muestras.push([
      numIntentos,
      numUsuarios,
      Math.round(intervaloProm * 100) / 100,
      Math.round(intervaloStd * 100) / 100,
      hora
    ]);
  }
  return muestras;
}
