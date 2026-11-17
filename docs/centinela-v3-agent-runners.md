# Centinela v3 — configuración de agentes automatizados

Este documento describe cómo registrar runners de laboratorio para **un único testbed autorizado**. No ejecuta pruebas al instalarse.

## Componentes

- Detector, coordinador y portal de autenticación de laboratorio: `https://bruteforce-detector-2uv4.onrender.com` (un único servicio Render).
- Los agentes consultan tareas y envían solicitudes a `POST /api/lab/agent/auth` en el mismo servicio.
- El endpoint valida token, tarea asignada, índice de intento, cuenta permitida, resultado esperado e IP de salida observada; después procesa y persiste el evento en el propio Centinela.
- No se requiere ni se debe configurar un segundo portal Render para este flujo.
- El detector almacena inicialmente `ground_truth_label=unknown`. Las etiquetas se aplican después de que la tarea completa, a partir del manifiesto independiente persistido en el experimento.

## Secretos requeridos

Generar un token de agente aleatorio con al menos 32 caracteres y guardarlo en el gestor de secretos; no subirlo a Git. El mismo valor se configura en:

1. Servicio detector: `CENTINELA_LAB_AGENT_TOKEN`.
2. Servicio de portal: `CENTINELA_LAB_AGENT_TOKEN`.
3. Cada runner autorizado: `CENTINELA_LAB_AGENT_TOKEN`.

Este token es distinto de `CENTINELA_INGEST_TOKEN`, utilizado por el portal para hablar con el detector.

Cada runner también requiere:
- `CENTINELA_LAB_AGENT_ID`: identificador único y estable, por ejemplo `runner-a`.
- `CENTINELA_LAB_CREDENTIALS_JSON`: objeto JSON con las contraseñas de las tres cuentas del testbed. Deben ser las mismas que usa el portal, con los secretos copiados manualmente desde el gestor de contraseñas de Render; nunca se guardan en Git.
- `CENTINELA_LAB_COORDINATOR_URL=https://bruteforce-detector-2uv4.onrender.com`.
- `CENTINELA_LAB_COORDINATOR_URL=https://bruteforce-detector-2uv4.onrender.com` (el runner usa este mismo origen para la captura HTTP).
- `CENTINELA_LAB_INVALID_PASSWORD`: cadena aleatoria que no coincida con ninguna contraseña real del testbed. El runner añadirá un sufijo por intento.

## Ejecutar un runner

Requisitos: Node.js 22 o superior, conectividad HTTPS hacia el portal y el detector.

En un checkout de la rama `feature/centinela-v3-automated-lab`:

```bash
npm install
npm run lab:agent
```

El proceso registra el identificador de agente y la IP observada por el coordinador, consulta tareas, espera al tiempo programado, ejecuta hasta 12 solicitudes por tarea y confirma cada `event_id`. Los logs no imprimen contraseñas ni direcciones IP en claro.

El agente benigno utiliza credenciales válidas únicamente en los pasos correctos del escenario benigno. Los intentos fallidos utilizan una credencial no válida. Los escenarios de ataque solo realizan intentos fallidos contra cuentas de laboratorio. No existe soporte para objetivos arbitrarios ni listas de credenciales externas.

## Direcciones IP independientes

Para probar el umbral distribuido de cuatro IP, el coordinador necesita cuatro runners activos cuyo `CF-Connecting-IP` observado por Render sea diferente.

- Cuatro procesos en una misma computadora o varios runners detrás de una misma NAT cuentan como **un solo origen**.
- Cuatro servicios Render en Oregon no garantizan cuatro IP distintas: Render publica rangos de salida compartidos por los servicios de la región. Cada registro se validará por la IP real observada; no se inferirá por el número de procesos.
- No se permite falsificar `X-Forwarded-For`, suplantar IP, usar cabeceras personalizadas como sustituto de origen ni utilizar proxies públicos.
- Si no se consiguen cuatro IP de salida reales, se puede estudiar el escenario de uno o varios orígenes disponibles, pero no se afirmará que se probó la detección distribuida de cuatro IP.

Render ofrece IP de salida dedicadas únicamente en planes Pro o superiores; la documentación indica un coste adicional de USD 100/mes por cada conjunto de tres direcciones IPv4 dedicadas. Esta opción no se activa automáticamente y requiere una decisión presupuestaria explícita. Para la fase inicial se priorizarán runners en redes independientes ya disponibles y se comprobarán sus IP antes de crear campañas.

## Límites operativos

- El catálogo actual fija: 7 solicitudes para benigno mixto, 6 para ráfaga, 8 para baja frecuencia y 2 por cada runner del escenario distribuido.
- Máximo 5 repeticiones por escenario y 12 solicitudes por tarea.
- Límite por IP del portal: 60 solicitudes/minuto.
- El escenario de baja frecuencia dura aproximadamente 9 minutos por ejecución.
- Las campañas no pueden solaparse dentro del mismo experimento.
- Detener una campaña no elimina los eventos ya capturados; los trabajos incompletos no se etiquetan automáticamente.
- El coordinador mantiene las colas y estados de los runners en memoria de una única instancia. Un reinicio/despliegue pierde las tareas activas; el manifiesto ya almacenado en Supabase permanece. No desplegar durante una campaña. Antes de una captura definitiva debe resolverse esta limitación o garantizarse que no habrá reinicios durante toda la campaña.
- La interfaz muestra las IP solo como prefijos HMAC y los eventos que el detector persiste. El canal Socket.IO exige sesión administrativa.

## Verificación previa

Antes de crear una campaña:

1. Confirmar el endpoint `/health` del portal y del detector.
2. Confirmar que el experimento v3 está activo y las fechas temporales fueron preregistradas.
3. Registrar los runners y confirmar al menos cuatro prefijos HMAC distintos para un test distribuido.
4. En cada runner confirmar que la versión de Node y las credenciales del testbed son válidas, sin registrar las contraseñas.
5. Ejecutar un único login benigno de prueba y confirmar un `event_id` persistido en el experimento correcto con `campaign_id`, `run_id`, `agent_id`, `scenario_id`, `actor_type` y `generation_method`.
6. Comprobar que la IP HMAC registrada por el agente coincide con el hash de IP del evento de autenticación y que el portal rechazó una petición con `X-Forwarded-For` falsificada si no coincide con `CF-Connecting-IP`.
7. Solo después de estas comprobaciones iniciar campañas controladas.

No generar miles de solicitudes hasta que el piloto demuestre captura completa, ausencia de duplicados, asignación temporal correcta, control de parada y persistencia de los manifiestos.
