# Protocolo operativo para capturar y evaluar eventos de autenticación reales

Este procedimiento recoge solicitudes HTTP de autenticación recibidas por la aplicación y procesadas por Centinela. No utiliza el generador de tráfico ni crea filas artificiales para el conjunto de estudio.

## 1. Preparar el entorno

1. Aplicar las migraciones de `supabase/schema.sql` y `supabase/migrations/` al proyecto Supabase.
2. Configurar en el backend de Centinela las variables descritas en [`.env.example`](../.env.example): `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `CENTINELA_HASH_SECRET`, `CENTINELA_INGEST_TOKEN`, `DASHBOARD_PASSWORD` y `SECRET_KEY`.
3. Configurar las mismas variables secretas en Render si el sistema se ejecuta allí. No subir el archivo `.env` ni copiar claves secretas al frontend.
4. Integrar la aplicación que autentica a los usuarios con Centinela. La llamada a `/registrar_intento` debe salir del backend de autenticación, no del navegador.

## 2. Crear el experimento antes de captar eventos

Autenticarse como administrador y llamar a:

```http
POST /api/experimentos
Content-Type: application/json

{
  "protocol_name": "centinela-auth-study-v1",
  "scenario": "authorized-authentication-testbed",
  "train_end_at": "2026-12-01T00:00:00Z",
  "validation_end_at": "2026-12-03T00:00:00Z",
  "description": "Protocolo preregistrado de captura de eventos de autenticación"
}
```

Las fechas deben ser futuras y expresarse en UTC. Se fijan antes de observar los resultados. La respuesta contiene el `experiment.id`; conservarlo en el cuaderno de laboratorio. Centinela no permite dos experimentos activos simultáneamente.

Los eventos se asignan automáticamente según su marca de tiempo del servidor:
- Antes de `train_end_at`: `train`.
- Desde `train_end_at` hasta antes de `validation_end_at`: `validation`.
- Desde `validation_end_at` en adelante: `test`.

## 3. Capturar solicitudes desde el backend que autentica

Después de cada intento de inicio de sesión, el backend de autenticación realiza una llamada autenticada a Centinela:

```bash
curl -X POST "$CENTINELA_URL/registrar_intento" \
  -H "Authorization: Bearer $CENTINELA_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "usuario": "account-key-00042",
    "ip": "198.51.100.25",
    "exitoso": false,
    "campaign_id": "bf-rapid-001"
  }'
```

El ejemplo de IP pertenece al rango reservado para documentación. En el estudio debe enviarse la IP de origen real verificada por el backend, siguiendo la configuración de proxies de confianza. `usuario` debe ser un identificador estable y seudonimizado, no una contraseña ni información innecesaria. `campaign_id` es un identificador de campaña definido en el manifiesto externo; se recomienda para agrupar los eventos correlacionados.

Centinela guarda HMAC de IP y usuario, nunca contraseñas. También conserva la marca temporal de recepción, el resultado de autenticación, el vector de características que utilizó el detector, su versión, las decisiones de los detectores y las latencias de inferencia. La fila inicia con `ground_truth_label = unknown`.

Una autenticación fallida no se etiqueta automáticamente como ataque. El backend debe llamar a Centinela para cada solicitud, incluidas las que son rechazadas por el sistema de autenticación o ya estaban bloqueadas. Para la ruta integrada `/registrar_intento`, no filtrar solicitudes antes de registrar el evento.

## 4. Etiquetar con evidencia independiente

La etiqueta real debe derivarse de una fuente ajena a la decisión de Centinela, por ejemplo:
- Un registro de usuarios legítimos o un manifiesto de sesiones autorizadas para actividad benigna.
- Un manifiesto de campaña con hosts de origen, cuenta objetivo, tipo de ataque, horario, número de solicitudes y autorización para una campaña de ataque controlada.

Para etiquetar un evento:

```http
POST /api/eventos/EVENT_UUID/etiqueta
Content-Type: application/json

{
  "label": "attack",
  "method": "authorized_campaign_manifest",
  "rationale": "El evento pertenece a la campaña bf-rapid-001, ejecutada desde el host de prueba 03 contra la cuenta de laboratorio.",
  "labeledBy": "researcher-01"
}
```

Usar `benign` únicamente con evidencia de actividad legítima; `attack` únicamente si el evento puede vincularse a una campaña documentada. Dejar como `unknown` los casos ambiguos. No usar `alerta_ml`, `alerta_reglas` o el bloqueo de Centinela para asignar la etiqueta: eso produciría circularidad.

El endpoint de exportación JSON permite consultar el conjunto pendiente de etiquetado:
```http
GET /api/dataset/capturado?experiment_id=EXPERIMENT_UUID
```

## 5. Entrenar y congelar el baseline

Al llegar a `train_end_at`, haber etiquetado los eventos del periodo de entrenamiento y antes de `validation_end_at`, llamar a:

```http
POST /api/experimentos/entrenar_con_eventos_capturados
```

Se requieren al menos 50 ventanas benignas confirmadas. El baseline se reconstruye usando solo eventos de entrenamiento etiquetados como benignos, no las ventanas que pudieron contener ataques identificados posteriormente. El entrenamiento queda congelado en los metadatos del experimento. No se permite volver a entrenar ese experimento; un ajuste nuevo requiere otro experimento.

Centinela restaura el mismo baseline desde Supabase después de un reinicio. El periodo de validación permanece separado y no se usa para el entrenamiento de la aplicación Node.

## 6. Finalizar y exportar

Después de `validation_end_at`, terminar la campaña de prueba, etiquetar los eventos del test y finalizar el experimento:

```http
POST /api/experimentos/EXPERIMENT_UUID/finalizar
```

Para exportar únicamente ese estudio, incluso después de finalizarlo:

```http
GET /api/dataset/capturado?experiment_id=EXPERIMENT_UUID&formato=csv
GET /api/experimentos/metricas_capturadas?experiment_id=EXPERIMENT_UUID
```

La API de métricas del servidor calcula los resultados únicamente con eventos de prueba etiquetados y solo si el baseline está congelado.

Si una escritura en Supabase falla después de que Centinela haya procesado una solicitud, el servicio detiene la captura para evitar ventanas con eventos perdidos. Revisar `/health` y los logs del servidor. Si la integridad del experimento no puede demostrarse, abortarlo registrando una razón:

```http
POST /api/experimentos/EXPERIMENT_UUID/abortar
Content-Type: application/json

{
  "reason": "Interrupción de persistencia durante la campaña; se descarta la ejecución incompleta."
}
```

Después de resolver el almacenamiento, crear un experimento nuevo. No sumar eventos de una ejecución abortada a las métricas de una ejecución completada.

## 7. Ejecutar la evaluación reproducible de scikit-learn

Guardar el CSV exportado como `centinela_eventos_capturados.csv` e instalar las dependencias:

```bash
python -m pip install -r requirements-empirical.txt
python empirical_auth_evaluation.py \
  --input centinela_eventos_capturados.csv \
  --output-dir empirical_results \
  --seed 42 \
  --bootstrap 1000
```

El evaluador:
- Rechaza filas marcadas como simuladas y cualquier esquema de características anterior a `centinela-auth-features-v2`.
- Reconstruye un baseline benigno a partir de los eventos `train` confirmados como benignos.
- Ajusta Isolation Forest, One-Class SVM con kernel RBF y LOF en modo novelty con scikit-learn.
- Calibra los umbrales usando exclusivamente `validation`.
- Calcula las métricas finales exclusivamente sobre `test`.
- Calcula intervalos por bootstrap agrupado por `campaign_id`, con IP seudonimizada como alternativa.
- Genera métricas, predicciones y manifiestos SHA-256 del CSV y de los artefactos.

Se requieren etiquetas benignas y de ataque en validación y prueba, además de al menos 50 eventos benignos de entrenamiento. Los eventos `unknown` se contabilizan y excluyen de las métricas de clasificación.

## 8. Qué puede afirmarse en el artículo

Los datos son solicitudes de autenticación capturadas por Centinela durante su operación en el entorno descrito. Los ataques del testbed deben denominarse tráfico experimental controlado y autorizado, no ataques espontáneos de usuarios externos ni tráfico de producción si no provienen de producción.

Distinguir los resultados de los detectores Node que ejecuta la aplicación de los modelos estándar de scikit-learn entrenados offline sobre las características capturadas. Los componentes TypeScript históricos llamados `one_class_svm` y `lof` son aproximaciones de distancia, no implementaciones canónicas de One-Class SVM y LOF; la comparación canónica se hace con los modelos scikit-learn del evaluador.

Archivar con la investigación el identificador del experimento, los cortes temporales, el manifiesto de campaña, la justificación de cada etiqueta, las versiones de código/configuración, el CSV original y todos los hashes. No eliminar `unknown` del recuento total al describir cobertura y calidad del etiquetado.
