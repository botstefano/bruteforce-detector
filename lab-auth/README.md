# Centinela Auth Lab

Servicio web independiente para realizar inicios de sesión del laboratorio y enviar los resultados a Centinela v2. Este servicio no tiene base de datos propia, panel de etiquetado ni motor de detección.

## Flujo de autenticación

1. El participante se identifica con una cuenta seudónima: `participante-01`, `participante-02` o `participante-03`.
2. El laboratorio valida su contraseña localmente.
3. El participante configura y presenta un código TOTP de seis dígitos generado por su aplicación autenticadora.
4. Solo después del resultado completo, el laboratorio envía a Centinela el identificador, el resultado, la IP verificada y la campaña `laboratorio-web-auth-v2`.
5. Centinela almacena el evento con su etiqueta inicial `unknown`; la auditoría y etiquetado se realizan allí.

Las contraseñas, los códigos TOTP y las semillas TOTP nunca se transmiten a Centinela ni se escriben en logs. Las semillas TOTP se mantienen como variables secretas en Render.

## Variables de entorno

Configurar en Render:

- `NODE_ENV=production`
- `CENTINELA_API_URL=https://bruteforce-detector-2uv4.onrender.com`
- `CENTINELA_INGEST_TOKEN`: el mismo secreto de ingesta configurado en el servicio detector.
- `LAB_CREDENTIALS_V2_JSON`: exactamente las tres cuentas seudónimas y sus contraseñas únicas de al menos 16 caracteres.
- `LAB_TOTP_SECRETS_JSON`: exactamente las mismas tres cuentas con semillas TOTP Base32 privadas de 32 caracteres.

No guardar estas variables en el repositorio ni compartir semillas TOTP entre participantes. Cada persona debe añadir su propia clave a Google Authenticator, Microsoft Authenticator, Aegis u otra aplicación compatible con TOTP. El primer paso de contraseña muestra la clave de configuración de esa cuenta; después, cada login exige el código actual de seis dígitos.

## Protección de intentos

- Máximo 5 fallos por cuenta en una ventana de 15 minutos.
- Al alcanzar el umbral, se aplica un bloqueo temporal de 15 minutos.
- Se conserva el límite adicional de 60 solicitudes por IP y minuto.
- Los intentos hechos durante un bloqueo se siguen enviando a Centinela como fallidos, para no perder observaciones del experimento.
- Los eventos de bloqueo generan una alerta de seguridad en los logs del servidor, sin incluir contraseña, código MFA, semilla TOTP ni IP en claro.
- Las contraseñas se comparan con SHA-256 y comparación de tiempo constante; el código TOTP usa HMAC-SHA1, seis dígitos y una tolerancia de una ventana de 30 segundos.

El bloqueo por cuenta es en memoria y se reinicia si Render reinicia o despliega la instancia. El límite por IP también es local a la instancia. Por ello, estas medidas son protecciones del testbed de una sola instancia, no un control de producción distribuido.

## Despliegue en Render

Servicio: `centinela-auth-lab`, rama `feature/lab-auth-render-service`, contexto Docker `./lab-auth`, Dockerfile `./lab-auth/Dockerfile`. El servicio escucha en `0.0.0.0` y usa el puerto de Render. Configurar el health check como `/health`.

## Verificación tras desplegar

1. Abrir `/health` y comprobar `status=ok`, `credentials_configured=true`, `mfa_configured=true`, `centinela_configured=true` y `campaign_id=laboratorio-web-auth-v2`.
2. Probar una autenticación correcta, incluyendo TOTP, y comprobar el ID del evento en la respuesta.
3. Realizar un fallo controlado y comprobar que el evento fallido también llega a Captura empírica.
4. En Centinela verificar `origin=integracion_autenticacion`, `campaign_id=laboratorio-web-auth-v2`, `is_simulated=false` y la partición temporal del protocolo activo.
5. Verificar el umbral de bloqueo solo en un ensayo controlado y después dejar que expire; evitar bloquear a los participantes durante la captura ordinaria.

Si Centinela no confirma la persistencia, el portal muestra un error y no afirma que el evento haya quedado almacenado. Comprueba primero Captura empírica antes de repetir un intento.

## Desarrollo local

Requiere Node.js 22 o superior. Define las mismas variables en un archivo local excluido de Git. Ejecuta:

```bash
cd lab-auth
node --env-file=.env server.js
```
