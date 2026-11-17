# Centinela v3 — Diseño de laboratorio automatizado

**Estado:** diseño y auditoría inicial; no desplegado.  
**Rama:** `feature/centinela-v3-automated-lab`  
**Base:** `fix/supabase-event-audit` en el commit `c8ea113984327fb0405f17902c8f41773e82de31`.  
**Fecha de inicio:** 2026-11-17.  
**Fecha objetivo de cierre de captura:** 2026-11-23 17:00, America/Lima (objetivo sujeto a criterios de calidad).

## 1. Propósito científico

Construir una evaluación experimental reproducible de un detector híbrido de fuerza bruta en eventos de autenticación HTTP. La investigación comparará reglas y detección de anomalías ante sesiones benignas, errores legítimos, ataques controlados desde un origen, ataques distribuidos y patrones de baja frecuencia.

Los agentes automatizados producirán solicitudes dirigidas exclusivamente al portal de laboratorio autorizado. Son **eventos HTTP realmente recibidos y procesados por la aplicación**, pero el comportamiento generador es automatizado y controlado. No se describirán como ataques espontáneos de Internet ni como actividad humana.

### Pregunta principal

¿En qué medida un sistema híbrido basado en reglas y aprendizaje automático identifica patrones controlados de fuerza bruta en eventos de autenticación HTTP y los distingue de errores legítimos, incluyendo actividad de uno o varios orígenes y patrones temporales diferentes?

### Preguntas secundarias

- ¿Cómo varía el rendimiento entre fuerza bruta rápida, lenta y distribuida?
- ¿Qué proporción de errores legítimos genera alertas?
- ¿Qué aporta la detección por reglas frente a los componentes de anomalías?
- ¿Se mantiene el rendimiento en campañas, agentes, orígenes y jornadas reservadas?
- ¿Cuál es el coste de procesamiento observado?

## 2. Auditoría inicial del repositorio (17-11-2026)

La rama base ya contiene componentes aprovechables:

- Captura empírica mediante `POST /demo/login` y `POST /registrar_intento`.
- Persistencia de eventos y experimentos en Supabase, con seudonimización HMAC.
- Separación temporal `train / validation / test`, etiquetado auditado y exportación CSV.
- Inicio de sesión administrativo con cookie HttpOnly y autenticación de Socket.IO.
- Emisión de eventos `nuevo_evento` y registros `bot_log` por Socket.IO.
- Panel `CentinelaWorkspace` y panel de captura empírica.

### Hallazgos que requieren corrección o diseño adicional

1. `src/bot_ataque.ts` es un simulador histórico, no un generador empírico aceptable: crea IP aleatorias y coloca valores en `X-Forwarded-For`, además de incluir una lista de credenciales codificadas. No se reutilizará ni se presentará como origen de IP reales.
2. Las rutas `/simular/*` generan eventos internos marcados como simulados y están bloqueadas durante experimentos empíricos. No se usarán para el dataset v3.
3. `CentinelaWorkspace` consulta datos mediante polling cada 30 segundos. El componente debe suscribirse al canal Socket.IO autenticado (o a un canal Realtime protegido) y reconciliar los eventos con Supabase para ofrecer monitorización casi en vivo.
4. `server.ts` emite actualmente objetos de evento que contienen IP y nombre de usuario sin seudonimizar. El nuevo flujo en vivo deberá emitir identificadores seudonimizados y metadatos mínimos, nunca contraseñas ni valores crudos identificativos.
5. El vector del detector contiene una hora UTC lineal. El v2 mostró un cambio horario entre particiones. Se evaluará excluir la hora absoluta o usar codificación cíclica; la opción se elegirá solo con datos de desarrollo/validación y se documentará como un nuevo esquema de características.
6. Los módulos TypeScript llamados One-Class SVM y LOF son aproximaciones heurísticas, no implementaciones canónicas. La comparación académica con esos algoritmos deberá utilizar implementaciones de referencia verificables (por ejemplo, el evaluador Python/scikit-learn ya existente) o describir las rutinas TypeScript como heurísticas propias.
7. Las reglas actuales son 5 fallos/IP/60 s, 8 fallos/IP/900 s y 4 IP diferentes por cuenta/120 s. Se conservarán inicialmente como baseline y cualquier ajuste se hará solo con validación.
8. El servicio Render tiene despliegue automático. La rama v3 no se conectará al servicio hasta que compile y supere pruebas. Cambiar la rama del servicio desplegará v3 sobre la URL actual y sustituirá la versión en ejecución; la rama histórica se conservará para reversión.

## 3. Diseño de los agentes automatizados

Se implementará un coordinador experimental y agentes separados del detector.

### Escenarios

- **B1 — Benigno exitoso:** autenticaciones correctas de cuentas de laboratorio.
- **B2 — Error benigno:** errores ocasionales y reintentos legítimos documentados.
- **A1 — Ráfaga desde un origen:** secuencia controlada de intentos fallidos desde un runner autorizado.
- **A2 — Distribuido:** campañas coordinadas hacia una cuenta de laboratorio desde múltiples runners con salidas de red verificadas.
- **A3 — Baja frecuencia:** intentos espaciados durante una ventana predefinida.
- **M1 — Mezcla benigna:** sesiones correctas y errores benignos intercalados para medir falsas alarmas y contaminación de ventanas.

### Origen de red

- Cada runner debe enviar solicitudes HTTP reales desde su entorno y Centinela debe observar la IP que llega al portal.
- No se admitirán IP inventadas, cabeceras `X-Forwarded-For` manipuladas desde los agentes ni suplantación de origen.
- Varios procesos detrás de una única NAT cuentan como un solo origen.
- Si no se pueden obtener suficientes salidas independientes verificadas, el estudio informará esa limitación y no afirmará haber probado distribución multi-IP.

### Restricciones de seguridad

- El coordinador aceptará únicamente el origen/host de laboratorio autorizado configurado en servidor.
- Las cuentas y credenciales de prueba se inyectarán mediante secretos de entorno; nunca se incluirán claves de cuentas reales en el repositorio.
- Los agentes tendrán límites explícitos de concurrencia, tasa, duración y número de solicitudes; habrá pausa y parada de emergencia.
- No se admitirán objetivos arbitrarios ni se ejecutarán pruebas contra servicios de terceros o producción.
- Los agentes no decidirán etiquetas según las alertas del detector.

## 4. Procedencia y verdad de referencia

Cada ejecución y evento deberá poder vincularse con:

- `experiment_id`, `phase`, `scenario_id`, `campaign_id`, `run_id` y `agent_id`.
- Método de generación (`automated_agent`) y tipo de actor (`benign_agent` o `attack_agent`).
- IP real observada por el servidor, almacenada solo como HMAC en la tabla de eventos.
- Tiempo de envío/recepción, resultado de autenticación y decisión de cada detector.
- Versión del código, configuración y esquema de características.

Los manifiestos independientes de cada campaña definirán cuentas objetivo, runners autorizados, intervalo temporal, patrón, número esperado de solicitudes y etiqueta. Se mantendrá un recuento de eventos capturados, no capturados, duplicados y `unknown`.

**Semántica importante:** que una solicitud sea HTTP real y se procese por el portal no significa que el comportamiento sea espontáneo o humano. El dataset describirá explícitamente generación automatizada. No se falsificará la procedencia mediante el campo `is_simulated`; se añadirán campos explícitos de actor y método de generación y se documentará el significado de ambos.

## 5. Protocolo experimental

Las fases se preregistrarán antes de recoger el conjunto definitivo:

1. **Desarrollo/piloto:** validar conectividad, persistencia, procedencia IP, límites, eventos en vivo y manifiestos. No se mezclará con las métricas finales.
2. **Train:** sesiones benignas verificadas; el baseline no usará eventos attack ni unknown.
3. **Validation:** escenarios benignos y controlados de ataque; selección de características, umbrales y configuración.
4. **Congelamiento:** registrar commit SHA, configuración, semilla, esquema de características, manifiestos y hashes.
5. **Test:** campañas y ejecuciones reservadas no utilizadas durante desarrollo o validación. No se reajustará el detector tras ver test.

La asignación deberá evitar que una misma campaña o ejecución correlacionada se reparta entre train, validation y test. También se cubrirán diferentes jornadas y horas dentro de cada fase para que la hora del día no quede confundida con la partición. Los eventos de una misma campaña no se tratarán como observaciones estadísticamente independientes.

La fecha objetivo de cierre es 2026-11-23 17:00 (America/Lima). Es un objetivo operativo, no una razón para saltarse el piloto, reducir la calidad del test ni mover los cortes después de observar resultados. Si no se cumplen los controles, el test se aplazará o el experimento se declarará incompleto.

## 6. Análisis predefinido

Se generarán, como mínimo:

- Recuento de capturados, perdidos, duplicados, desconocidos y etiquetados por fase y escenario.
- Matrices de confusión, precisión, recall, F1, FPR, especificidad y exactitud.
- Precision–Recall curve / PR-AUC cuando las puntuaciones lo permitan.
- Métricas separadas por escenario, campaña y origen.
- Intervalos de confianza y remuestreo agrupado por campaña o ejecución; no bootstrap ingenuo por solicitud individual.
- Latencia p50/p95 y media, distinguiendo inferencia interna y extremo a extremo.
- Comparación de reglas, modelo(s) y combinación.
- Análisis de errores, falsas alarmas benignas, sensibilidad a la hora y ablaciones elegidas exclusivamente en validación.
- Manifiestos SHA-256 de los datos exportados, configuraciones y artefactos de evaluación.

El tamaño final no se fijará solo por una cifra arbitraria de solicitudes. Se planificará a partir de la cantidad de campañas/ejecuciones independientes, cobertura de escenarios y precisión de las estimaciones. Si hay muchos eventos repetidos en pocas campañas, se informará la dependencia y se evitará presentar el volumen bruto como tamaño muestral independiente.

## 7. Interfaz y monitorización

La interfaz mostrará:

- Estado por agente: preparado, activo, pausado, finalizado o error.
- Campaña, escenario, run ID, origen pseudonimizado y solicitudes completadas.
- Eventos persistidos y respuesta HTTP, alertas de reglas/ML y latencia.
- Estado de las fases, cortes UTC/hora Lima y estado de congelamiento.
- Controles de iniciar, pausar y detener con límites de seguridad.

El canal en vivo será privado y requerirá la sesión administrativa existente. Se mostrarán hashes/identificadores pseudonimizados, no IP ni cuentas crudas. Los datos del monitor se reconciliarán periódicamente con Supabase para no perder eventos si un socket se desconecta.

La vista en vivo distinguirá claramente **verdad de referencia** (manifiesto) y **predicción del detector**, para evitar fuga de etiquetas.

## 8. Criterios de aceptación antes del despliegue

- Compilación TypeScript y build Vite satisfactorios.
- Pruebas de unidad para escenarios, límites y asignación de etiquetas desde manifiestos.
- Prueba de integración end-to-end contra el portal de laboratorio: el evento llega al detector y se persiste una sola vez.
- Verificación de que las IP mostradas son las observadas realmente, no las declaradas por el cliente.
- Verificación de que el canal en vivo requiere sesión admin y no expone IP/usuario sin seudonimizar.
- Prueba de parada, límites de tasa, reanudación segura y recuperación ante caída de Supabase.
- Comprobación de que train/validation/test y campañas se mantienen separados.
- No activar generación de tráfico durante una prueba de build ni contra objetivos no autorizados.

## 9. Secuencia de implementación

1. Completar auditoría del servidor, componentes, esquema y evaluador Python.
2. Añadir migración compatible para metadatos de actor/escenario/ejecución y su política RLS.
3. Implementar coordinador y manifiestos inmutables de campañas.
4. Implementar runner de agentes restringido a host autorizado y que use la IP de red real.
5. Incorporar el monitor en vivo a la interfaz existente y reducir el polling a reconciliación de respaldo.
6. Revisar características y detector; separar claramente salidas Node y modelos canónicos offline.
7. Automatizar exportación y evaluación estadística.
8. Ejecutar piloto, verificar integridad, preregistrar y después iniciar train/validation/test.
9. Preparar manuscrito únicamente con métricas calculadas desde los artefactos congelados.

## 10. Aislamiento de experimentos v2 y v3

El arranque de v3 solo restaura experimentos cuyo nombre de protocolo contiene `v3`. La creación de un experimento v3 solo comprueba conflictos con otros experimentos v3 activos. Un experimento v2 que siga marcado como `running` no se adopta ni recibe eventos de v3. Cada evento nuevo se vincula al identificador del experimento v3 seleccionado y permanece separado en Supabase.

Antes de la primera captura v3 se debe crear un **experimento nuevo**, con nombre de protocolo que incluya `v3` y con los tres cortes temporales (train, validation y test). No reutilizar el experimento que se creó para el piloto v2. La captura y evaluación v3 deben exportarse filtrando por el nuevo `experiment_id`.

## 11. Protección de v2

Esta rama se creó desde `fix/supabase-event-audit`. No se hará merge a `master`, no se cambiarán etiquetas ni datos v2 y no se utilizará el CSV histórico como parte de v3. El servicio Render actual no debe cambiar de rama hasta que esta rama pase los criterios de aceptación y el usuario reciba un resumen de los riesgos del despliegue.
