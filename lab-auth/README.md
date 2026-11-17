# Centinela Auth Lab

Servicio web independiente para realizar inicios de sesión de laboratorio y enviar los resultados a Centinela v3. Mantiene una ruta privada autenticada para agentes experimentales. No mantiene una base de datos propia, panel de etiquetado ni motor de detección.

## Cuentas de participantes

- `ronan`
- `andy`
- `stefano`

Las contraseñas son únicas y se mantienen como secretos de entorno en Render. No se guardan en el repositorio ni se envían a Centinela.

## Flujo

1. El participante introduce su usuario y contraseña.
2. Resuelve una comprobación CAPTCHA aritmética, generada y validada en el servidor, con vencimiento y uso único.
3. El laboratorio valida la contraseña de forma local.
4. El laboratorio transmite a Centinela solamente el usuario, el resultado final de autenticación, la IP verificada y los identificadores de campaña/ejecución/agente/escenario. No transmite la contraseña.

Los agentes autorizados usan `POST /agent/login` con `CENTINELA_LAB_AGENT_TOKEN`. Esta ruta no solicita CAPTCHA interactivo, pero acepta exclusivamente las tres cuentas del testbed, aplica límites por IP y exige metadatos de campaña válidos. No hay endpoint para un destino arbitrario.
5. Centinela almacena el evento con etiqueta inicial `unknown`; la auditoría y el etiquetado se realizan allí.

Los CAPTCHA incorrectos o caducados y los envíos que activan el campo trampa se rechazan antes de la autenticación y no se contabilizan como fallos de contraseña en el conjunto empírico. Así se evita contaminar los datos de autenticación con errores de la propia comprobación anti-bot.

## Protecciones para esta fase experimental

- CAPTCHA aritmético simple, distinto por intento, generado en el servidor, asociado a la IP, de un solo uso y con cinco minutos de caducidad.
- Campo honeypot oculto para detectar formularios automatizados básicos.
- Límite de 60 solicitudes de login por IP por minuto.
- **No hay bloqueo por cuenta ni bloqueo por número de contraseñas incorrectas.** Los fallos de contraseña superado el CAPTCHA se envían a Centinela para estudiar la respuesta del detector.
- Cabeceras de seguridad, validación de mismo origen, límite del tamaño del cuerpo, HTTPS en producción y verificación de la IP de origen de Render.
- Las contraseñas se comparan localmente con SHA-256 y comparación de tiempo constante. No se almacenan ni registran.

El CAPTCHA aritmético es una defensa ligera para un testbed experimental, no equivale a un servicio CAPTCHA avanzado ni convierte el portal en un sistema de producción. El límite por IP es local a la única instancia y se reinicia al reiniciar o desplegar Render.

## Variables de entorno de Render

- `NODE_ENV=production`
- `CENTINELA_API_URL=https://bruteforce-detector-2uv4.onrender.com`
- `CENTINELA_INGEST_TOKEN`: secreto de ingesta servicio-a-servicio configurado en el detector.
- `CENTINELA_LAB_AGENT_TOKEN`: secreto aleatorio de al menos 32 caracteres compartido solo con el coordinador v3 y los runners autorizados.
- `LAB_CAMPAIGN_ID`: identificador de la campaña activa. Usa un valor distinto para validación y prueba; los eventos nuevos lo conservarán como `campaign_id`. Por compatibilidad, el valor predeterminado es `laboratorio-web-auth-v2`.
- `LAB_CREDENTIALS_V2_JSON`: objeto JSON con exactamente `ronan`, `andy` y `stefano`, cada uno con contraseña distinta de 16 a 256 caracteres.

No se necesita una variable de semillas TOTP para esta versión.

## Despliegue

Servicio Render `centinela-auth-lab`, rama `feature/lab-auth-v3-agent-ingest`, contexto Docker `./lab-auth` y Dockerfile `./lab-auth/Dockerfile`. Health check: `/health`. La ruta nueva aún no debe usarse hasta que se despliegue esta rama y se configuren los dos tokens secretos.

## Verificación

1. Abrir `/health` y comprobar `status=ok`, `credentials_configured=true`, `captcha_configured=true`, `centinela_configured=true`, el `campaign_id` correspondiente a la fase activa y `account_lockout_enabled=false`.
2. Probar un login válido y confirmar su identificador de evento.
3. Probar una contraseña incorrecta con CAPTCHA correcto y confirmar un evento fallido en Captura empírica.
4. Probar un CAPTCHA incorrecto y confirmar que no se crea un evento de autenticación.
5. En Centinela verificar `origin=integracion_autenticacion`, el `campaign_id` esperado, `is_simulated=false` y la partición temporal del experimento activo.
6. Etiquetar únicamente con evidencia independiente de sesiones/campañas autorizadas, nunca a partir de alertas del detector.

Si Centinela no confirma la persistencia, el laboratorio muestra un error y no afirma que el evento se haya guardado. Comprueba Captura empírica antes de repetirlo.

## Desarrollo local

Requiere Node.js 22 o superior. Define las variables requeridas en un archivo local excluido de Git y ejecuta:

```bash
cd lab-auth
node --env-file=.env server.js
```


## Agentes automatizados Centinela v3

- La ruta `POST /agent/login` requiere `Authorization: Bearer $CENTINELA_LAB_AGENT_TOKEN` y metadatos válidos de campaña y ejecución.
- Las solicitudes deben proceder de los runners configurados y utilizar una cuenta del testbed. Los agentes no pueden definir el destino ni la IP observada.
- En producción, el portal acepta la IP solo desde `CF-Connecting-IP` junto con `CF-Ray` de la capa Cloudflare/Render. No confía en la primera entrada de `X-Forwarded-For`, porque puede contener un valor introducido por el cliente.
- Para el escenario distribuido, cada agente debe ejecutar desde una salida de red pública distinta, verificada en el registro del coordinador. Procesos distintos detrás de una misma NAT cuentan como una sola IP.
- No se debe enviar `expected_label` ni puntuaciones del manifiesto al detector. La verdad de referencia se conserva en el manifiesto independiente del coordinador.
- Los CAPTCHA fallidos no se contabilizan como errores de autenticación; el agente interno omite el CAPTCHA interactivo solo porque se autentica con el token de agente y usa las cuentas cerradas del laboratorio.
