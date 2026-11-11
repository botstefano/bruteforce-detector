# Centinela Auth Lab

Servicio web independiente para realizar inicios de sesión de laboratorio y enviar el resultado de cada intento al detector Centinela v2. Este servicio no tiene base de datos propia, panel de etiquetado ni motor de detección.

## Flujo

1. El participante envía usuario y contraseña por HTTPS a este servicio.
2. El laboratorio valida las credenciales en el servidor.
3. El laboratorio envía a Centinela solamente `usuario`, `exitoso`, la IP verificada y un `campaign_id`.
4. Centinela procesa el evento y lo almacena en la tabla empírica existente de Supabase.
5. El evento aparece en **Captura empírica** de Centinela con etiqueta inicial `unknown`.
6. La revisión y el etiquetado se realizan únicamente desde Centinela.

Las contraseñas nunca se incluyen en la petición a Centinela ni se escriben en logs o en Supabase.

## Despliegue en Render

Crear un nuevo **Web Service** usando el repositorio `botstefano/bruteforce-detector`:

- **Branch:** `feature/lab-auth-render-service`
- **Root Directory:** `lab-auth`
- **Runtime:** Node
- **Build Command:** `npm install`
- **Start Command:** `npm start`
- **Health Check Path:** `/health`
- **Region:** la misma región del servicio Centinela, si está disponible.

Render asigna al servicio su propio subdominio `.onrender.com`. El laboratorio escucha en `0.0.0.0` y utiliza el puerto proporcionado por Render.

## Variables de entorno obligatorias

Configurar en el nuevo servicio:

- `NODE_ENV=production`
- `CENTINELA_API_URL=https://bruteforce-detector-2uv4.onrender.com`
- `CENTINELA_INGEST_TOKEN`: copiar el valor privado ya configurado en el servicio experimental de Centinela. Debe ser el mismo secreto en ambos servicios; nunca escribirlo en el repositorio.
- `LAB_CREDENTIALS_JSON`: objeto JSON con exactamente las cuentas `lab01`, `lab02` y `lab03`.

Ejemplo de formato, usando valores nuevos y secretos (no reutilizar las contraseñas compartidas anteriormente):

```json
{
  "lab01": "GENERAR_UNA_CLAVE_ALEATORIA_UNICA_DE_16_CARACTERES_O_MAS",
  "lab02": "GENERAR_OTRA_CLAVE_ALEATORIA_UNICA_DE_16_CARACTERES_O_MAS",
  "lab03": "GENERAR_OTRA_CLAVE_ALEATORIA_UNICA_DE_16_CARACTERES_O_MAS"
}
```

Cada cuenta debe tener una contraseña única de al menos 16 caracteres. El servicio no inicia si falta una cuenta, si las claves son repetidas o si no cumplen la longitud mínima.

No es necesario configurar CORS: el navegador se comunica únicamente con el laboratorio y el laboratorio se comunica servidor a servidor con Centinela.

## Verificación

1. Abrir `https://<servicio-lab>.onrender.com/health` y confirmar `status: ok`, `credentials_configured: true` y `centinela_configured: true`.
2. Probar un login correcto de una de las cuentas.
3. Comprobar que la respuesta indica que el evento fue registrado y devuelve su identificador.
4. Probar un error de contraseña intencional y controlado.
5. Abrir el panel experimental de Centinela, entrar en **Captura empírica**, actualizar el estado y localizar ambos eventos.
6. Confirmar que `origin=integracion_autenticacion`, `campaign_id=laboratorio-web-auth-v1`, `is_simulated=false` y que la partición temporal coincide con la fecha del evento.
7. Etiquetar los eventos en Centinela solamente después de verificar la actividad y su evidencia.

Si Centinela no confirma el registro, el laboratorio muestra un error y no afirma que el evento se haya guardado. No repitas inmediatamente ese intento: primero revisa Captura empírica para evitar duplicados.

## Seguridad e IP de origen

- El token de ingesta existe solo en variables de entorno del servidor.
- La contraseña se valida en este servicio y nunca se reenvía a Centinela.
- Se utiliza el encabezado `X-Forwarded-For` que Render documenta para identificar la IP del cliente. El servicio toma la primera dirección válida de la cadena y no acepta una IP suministrada por el navegador en el cuerpo JSON.
- Se aplica un límite de 60 solicitudes de login por minuto y por IP.
- Las respuestas incluyen políticas de no-cache, CSP, protección contra framing y otras cabeceras de seguridad.
- La aplicación no guarda sesiones ni contraseñas. Es un testbed de login, no un portal de producción.

Referencias operativas:
- Render Web Services: https://render.com/docs/web-services
- Render Monorepo Support: https://render.com/docs/monorepo-support
- Render sobre IP real y protección de aplicaciones: https://render.com/articles/how-render-handles-ddos-attacks

## Desarrollo local

Requiere Node.js 22 o superior.

```bash
cd lab-auth
cp .env.example .env
# Completar .env con credenciales nuevas y el token del servicio experimental.
node --env-file=.env server.js
```

En local, la IP se toma del socket local. En producción, el servicio exige una IP válida en `X-Forwarded-For` antes de enviar el evento a Centinela.
