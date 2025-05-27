# Vuln-Reporter

## Script 

### Documentación del Script de Monitoreo de Vulnerabilidades

Este documento describe detalladamente cada componente y función del script de Python encargado de monitorear vulnerabilidades de seguridad desde dos fuentes (Kubernetes y Red Hat), procesar los datos, enviar alertas a un webhook de Microsoft Teams y exponer métricas para Prometheus.

---

#### Tabla de Contenidos

1. Descripción General

2. Configuración y Variables Globales

3. Funciones de Gestión de Estado

   - `load_last_run_state`

   - `save_last_run_state`

4. Funciones de Formateo

   - `get_severity_text_and_color`

1. Funciones de Extracción de Vulnerabilidades

   - `fetch_redhat_vulnerabilities`
 
   - `fetch_kubernetes_vulnerabilities`

   - `parse_kubernetes_content_text`

6. Funciones de Procesamiento y Envío de Alertas

   - `post_to_teams`

   - `process_kubernetes_vulnerabilities`

   - `process_redhat_vulnerabilities`

6. Bucle Principal y Exposición de Métricas

7. Referencias

---

#### Descripción General

El script realiza las siguientes tareas de manera cíclica:

1. Carga el estado de la última ejecución (`last_check_time` y `processed_ids`).

2. Inicia un servidor HTTP para exponer métricas Prometheus.

3. Cada 5 minutos:

   - Obtiene vulnerabilidades de Kubernetes y Red Hat.

   - Filtra, ordena y deduplica los registros usando el estado previo.

   - Envía alertas a Microsoft Teams para nuevas vulnerabilidades.

   - Actualiza y expone métricas de número de vulnerabilidades críticas.

   - Guarda el nuevo estado en disco (`run_state.json`).

---

#### Configuración y Variables Globales

- **`STATE_FILE`**: Ruta al JSON que almacena el estado de la última ejecución.

- **`TEAMS_WEBHOOK`**: URL del webhook de Microsoft Teams obtenido de la variable de entorno `TEAMS_WEBHOOK`.

- **`METRICS_PORT`**: Puerto en el que el servidor Prometheus escucha (por defecto, `8000`).

- **`KUBERNETES_CVE_FEED_URL`**: URL del feed oficial de CVEs de Kubernetes.

- **`REDHAT_API_URL`**: Endpoint de la API pública de Red Hat Security Data.

- **Constantes de fuente**:

   - `SOURCE_KUBERNETES = "Kubernetes Official CVE Feed"`

   - `SOURCE_REDHAT = "Red Hat (OpenShift)"`


Además, se configura el logger con nivel `INFO` y formato estándar.

---

#### Funciones de Gestión de Estado

##### `load_last_run_state(filename, default_timedelta_hours=1)`

```python
def load_last_run_state(filename, default_timedelta_hours=1):
    """
    Carga el estado previo (última fecha y conjunto de IDs procesados).
    Si no existe o está corrupto, devuelve:
      - last_check: ahora - default_timedelta_hours
      - processed_ids: set()
    Retorna: (last_check_datetime, processed_ids_set)
    """
```

- **Propósito**: Mantener persistencia entre ejecuciones para evitar duplicar alertas.

- **Parámetros**:

   - `filename` (str): Ruta al archivo JSON de estado.

   - `default_timedelta_hours` (int): Horas a retroceder si no hay estado previo.

- **Flujo**:

   1. Intenta leer y parsear el JSON.

   2. Convierte `last_check_time_utc_iso` a `datetime` UTC naive.

   3. Construye un `set` con los IDs procesados.

   4. Si falla (archivo no existe o JSON inválido), devuelve:

       - `last_check = now - default_timedelta_hours`

       - `processed_ids = set()`

- **Retorno**: Tuple[`datetime`, `set(str)`].

---

##### `save_last_run_state(filename, last_check_time_utc, processed_ids)`

```python
def save_last_run_state(filename, last_check_time_utc, processed_ids):
    """
    Guarda el estado actual en JSON:
      - last_check_time_utc_iso: timestamp ISO con sufijo 'Z'
      - processed_ids: lista de CVE IDs únicos
    """
```

- **Propósito**: Serializar el estado actual tras cada ciclo.

- **Parámetros**:

   - `filename` (str): Archivo de salida.

   - `last_check_time_utc` (datetime): Marca temporal UTC de esta ejecución.

   - `processed_ids` (iterable de str): IDs de CVEs ya procesados.

- **Flujo**:

   1. Construye un dict con la clave `last_check_time_utc_iso` (ISO+"Z") y la lista de `processed_ids`.

   2. Serializa a JSON con indentación.

   3. Registra éxito o error en el logger.

---

#### Funciones de Formateo

##### `get_severity_text_and_color(score)`

```python
def get_severity_text_and_color(score):
    """
    Convierte un score CVSS en texto descriptivo y color hex para tarjetas Teams.

    Criterios:
      - >=9.0: Crítica ("FF0000")
      - >=7.0: Alta    ("FFA500")
      - >=4.0: Media   ("FFFFE0")
      - >0.0: Baja     ("90EE90")
      - 0.0 o None: Informativa/Desconocida ("D3D3D3")
    """
```

- **Entrada**: `score` numérico o `None`.

- **Salida**: Tuple[`str` (texto), `str` (código hex color)].

- **Uso**: Personalizar el aspecto visual de las alertas.

---

#### Funciones de Extracción de Vulnerabilidades

##### `fetch_redhat_vulnerabilities(start_date_utc_naive)`

```python
def fetch_redhat_vulnerabilities(start_date_utc_naive):
    params = {"after": start_date_utc_naive.strftime("%Y-%m-%d")}
    resp = requests.get(REDHAT_API_URL, params=params, timeout=30)
    return resp.json() if lista else []
```

- **Propósito**: Obtener CVEs desde la API de Red Hat publicados después de `start_date`.

- **Parámetros**:

   - `start_date_utc_naive` (`datetime` sin tz): Fecha mínima de publicación.

- **Retorno**: Lista de objetos JSON (cada uno con campos como `CVE`, `public_date`, `cvss3_score`).

- **Manejo de errores**: Captura excepciones de red o parseo JSON, retorna lista vacía.


##### `fetch_kubernetes_vulnerabilities(start_date_utc_naive)`

```python
def fetch_kubernetes_vulnerabilities(start_date_utc_naive):
    resp = requests.get(KUBERNETES_CVE_FEED_URL, timeout=30)
    data = resp.json()
    items = data.get("items", [])
    # Parseo de fechas y orden descendente
    return 2 items más recientes
```

- **Propósito**: Obtener y filtrar los 2 CVEs más recientes del feed oficial de Kubernetes.

- **Pasos**:

   1. Descarga el JSON completo.

   2. Itera cada item, parsea `date_published` a `datetime` UTC naive.

   3. Ordena todos los items por fecha descendente.

   4. Devuelve los 2 primeros.

- **Manejo de errores**: Captura fallos de conexión o parseo, retorna lista vacía.

##### `parse_kubernetes_content_text(content_text)`

```python
def parse_kubernetes_content_text(content_text):
    # Busca "Score: X.Y" vía regex, devuelve (float(score), "N/A")
```

- **Propósito**: Extraer el valor del CVSS Score embebido en el texto libre.

- **Entrada**: `content_text` (str) con posible patrón "Score: X.Y".

- **Salida**: Tuple[`float` score, `str` vector placeholder].

- **Regex**: `r"Score:\s*(\d{1,2}\.\d)"`.

---

#### Funciones de Procesamiento y Envío de Alertas

##### `post_to_teams(cve_id, title, description, score, url, source_name, published_date=None, vector_string=None)`

```python
def post_to_teams(...):
    severity_text, color = get_severity_text_and_color(score)
    card = {...}
    requests.post(TEAMS_WEBHOOK, json=card)
    return True/False
```

- **Propósito**: Enviar un mensaje enriquecido a Microsoft Teams para cada CVE.

- **Parámetros**:

   - `cve_id` (str): Identificador CVE.

   - `title` (str): Título personalizado.

   - `description` (str): Resumen de la vulnerabilidad.

   - `score` (float): Puntuación CVSS.

   - `url` (str): Enlace a detalles.

   - `source_name` (str): Nombre de la fuente.

   - `published_date` (str, opcional): Fecha de publicación.

   - `vector_string` (str, opcional): Cadena vectorial CVSS.

- **Construcción de la tarjeta**:

   - `themeColor` según severidad.

   - Sección de `facts` con campos clave.

   - Si `score >= 9.0`, se añade etiqueta `prometheus_alert_tag`.

- **Manejo de errores**: Captura excepciones al enviar HTTP, retorna `False` y registra error.

#### `process_kubernetes_vulnerabilities(last_check_time, processed_ids)`

```python
def process_kubernetes_vulnerabilities(last_check_time, processed_ids):
    items = fetch_kubernetes_vulnerabilities(last_check_time)
    for item in items:
        if item.id not en processed_ids:
            parse, enviar...
            processed_ids.add(id)
    return (count_sent, critical_count)
```

- **Propósito**: Filtrar y procesar CVEs de Kubernetes evitando duplicados.

- **Flujo**:

   1. Obtener los 2 items más recientes.

   2. Para cada item:

       - Ignorar si ya fue procesado.

       - Extraer `id`, `summary`, `score`, `published_date`, `url`.

       - Incrementar contador si es crítica (`score >= 9`).

       - Enviar alerta con `post_to_teams`.

       - Agregar ID a `processed_ids`.

- **Retorno**: Tuple[`int` sent_messages, `int` critical_found_count].

##### `process_redhat_vulnerabilities(last_check_time, processed_ids)`

```python
def process_redhat_vulnerabilities(last_check_time, processed_ids):
    items = fetch_redhat_vulnerabilities(ninety_days_ago)
    filtrar, ordenar y tomar 2 más recientes
    for item in items:
        similar a Kubernetes...
```

- **Diferencias clave**:

   - Usa un rango de 90 días para la consulta inicial.

   - Ordena en Python y toma 2 primeros.

   - Obtiene `CVE`, `bugzilla_description`, `cvss3_score`, `public_date`, `resource_url`.

   - Mismo mecanismo de deduplicación y envío.

---

#### Bucle Principal y Exposición de Métricas

```python
if __name__ == "__main__":
    last_check_time, processed_ids = load_last_run_state(STATE_FILE)
    start_http_server(METRICS_PORT)
    while True:
        now = datetime.utcnow()
        k8s_sent, k8s_crit = process_kubernetes_vulnerabilities(...)
        rh_sent, rh_crit = process_redhat_vulnerabilities(...)
        cve_critical_total.labels(...).set(...)
        save_last_run_state(...)
        time.sleep(300)
```

1. **Inicialización**:

   - Carga estado previo.

   - Inicia servidor Prometheus en `METRICS_PORT`.

2. **Ciclo**:

   - Cada 5 minutos (300s), registra `now`.

   - Procesa vulnerabilidades de ambas fuentes.

   - Actualiza métricas de Gauges Prometheus:

       - `cve_critical_total` por fuente.

   - Guarda el estado.

   - Duerme el intervalo.

---

#### Referencias

- [Python requests Documentation](https://docs.python-requests.org/)

- [Prometheus Python Client](https://github.com/prometheus/client_python)

- [Microsoft Teams Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet#key-features-of-incoming-webhooks)

---

## Despliegue

### Python

Construcción de la imagen con python
```bash
$ minikube image build -t vuln_reporter:1.0 .
```

Despliegue del pod
```bash
$ kubectl apply -f deployment.yaml
```

### Helm 

Instalación de Helm
```bash
$ curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3

$ chmod 700 get_helm.sh

$ ./get_helm.sh
```

Instalación de los repositorios
```bash
$ helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

$ helm repo update
```

Despliegue de Prometheus
```bash
$ helm upgrade --install prometheus prometheus-community/prometheus -n monitoring --create-namespace -f values.yaml
```

Despliegue de Grafana
```bash
$ helm install grafana grafana/grafana
```

Credenciales de Grafana

User: admin
Pass:
```bash
$ kubectl get secret -n monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
```

Conexión de Grafana con Prometheus 
```bash
http://prometheus-server.monitoring.svc.cluster.local:80
```
