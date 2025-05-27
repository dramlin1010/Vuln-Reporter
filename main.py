from datetime import datetime, timedelta, timezone
import os
import time
import logging
import requests
import configparser
import re
import json
from prometheus_client import start_http_server, Gauge

STATE_FILE = "run_state.json"

config = configparser.ConfigParser()
TEAMS_WEBHOOK = os.getenv("TEAMS_WEBHOOK")
METRICS_PORT = 8000

KUBERNETES_CVE_FEED_URL = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
REDHAT_API_URL = "https://access.redhat.com/labs/securitydataapi/cve.json"

SOURCE_KUBERNETES = "Kubernetes Official CVE Feed"
SOURCE_REDHAT = "Red Hat (OpenShift)"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(funcName)s - %(message)s"
)

last_check_time = None

cve_critical_total = Gauge(
    'cve_critical_total',
    'Número de vulnerabilidades críticas (CVSS>=9) encontradas en la última revisión por fuente',
    ['source']
)

"""
No eliminar para evitar deduplicación basada en el tiempo. Con last_run podemos evitar que en los reinicios meta alertas
repetidas, ya que seria redundante.
"""

def load_last_run_state(filename, default_timedelta_hours=1):
    """
    Carga el estado previo (última fecha y conjunto de IDs procesados).
    Si no existe o está corrupto, devuelve:
      - last_check = ahora - default_timedelta_hours
      - processed_ids = set()
    Retorna: (last_check_datetime, processed_ids_set)
    """
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            # Timestamp
            last_time_str = data.get("last_check_time_utc_iso")
            if last_time_str:
                dt = datetime.fromisoformat(last_time_str.replace('Z', '+00:00'))
                last_check = dt.astimezone(timezone.utc).replace(tzinfo=None)
            else:
                last_check = datetime.utcnow() - timedelta(hours=default_timedelta_hours)
            # IDs procesados
            processed = set(data.get("processed_ids", []))
            return last_check, processed
    except (FileNotFoundError, json.JSONDecodeError):
        logging.info(f"Estado no encontrado o inválido en '{filename}'. Usando valores por defecto.")
        return datetime.utcnow() - timedelta(hours=default_timedelta_hours), set()

def save_last_run_state(filename, last_check_time_utc, processed_ids):
    """
    Guarda el estado actual en JSON:
      - last_check_time_utc_iso: timestamp ISO con sufijo 'Z'
      - processed_ids: lista de CVE IDs únicos
    Parámetros:
      filename            – ruta del JSON de estado
      last_check_time_utc – datetime UTC de esta ejecución
      processed_ids       – iterable de IDs ya procesados
    """
    try:
        data = {
            "last_check_time_utc_iso": last_check_time_utc.isoformat() + "Z",
            "processed_ids": list(processed_ids)
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        logging.info(f"Estado guardado en '{filename}'.")
    except Exception as e:
        logging.error(f"Error al guardar estado: {e}")

def get_severity_text_and_color(score):
    score = float(score) if score is not None else 0.0
    if score >= 9.0:
        return "Crítica", "FF0000"
    if score >= 7.0:
        return "Alta", "FFA500"
    if score >= 4.0:
        return "Media", "FFFFE0"
    if score > 0.0:
        return "Baja", "90EE90"
    return "Informativa/Desconocida", "D3D3D3"

def fetch_redhat_vulnerabilities(start_date_utc_naive):
    params = {"after": start_date_utc_naive.strftime("%Y-%m-%d")}
    logging.info(f"Consultando Red Hat API: {params}")
    try:
        resp = requests.get(REDHAT_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []
    except (requests.exceptions.RequestException, ValueError) as e:
        logging.error(f"Error Red Hat API: {e}")
    return []

def post_to_teams(cve_id, title, description, score, url, source_name, published_date=None, vector_string=None):
    severity_text, color = get_severity_text_and_color(score)
    display_score = f"{score:.1f}" if score is not None else "N/A"
    card_title = f"🚨 Alerta Vulnerabilidad ({severity_text}) - {source_name}: {cve_id}"
    card_summary = f"Vulnerabilidad {cve_id} ({severity_text} - Score: {display_score})"
    facts = [{"name": "CVE ID:", "value": cve_id}, {"name": "Puntuación CVSS:", "value": f"**{display_score}** ({severity_text})"}]
    if published_date: facts.append({"name": "Fecha Publicación:", "value": published_date})
    facts.append({"name": "Fuente:", "value": source_name})
    facts.append({"name": "Más Detalles:", "value": f"[Ver detalles]({url})"})

    card = {"@type": "MessageCard", "@context": "http://schema.org/extensions", "themeColor": color, "summary": card_summary, "title": card_title,
            "sections": [{"activityTitle": "Descripción de la Vulnerabilidad:", "activitySubtitle": description[:250] + ("..." if len(description) > 250 else ""), "facts": facts, "markdown": True}]}

    if score >= 9.0:
        card["prometheus_alert_tag"] = "critical_vulnerability"

    try:
        response = requests.post(TEAMS_WEBHOOK, json=card, timeout=10)
        response.raise_for_status()
        logging.info(f"Mensaje para {cve_id} ({severity_text}) enviado a Teams.")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al enviar a Teams para {cve_id}: {e}{f' Respuesta: {response.text}' if 'response' in locals() and response is not None else ''}")
        return False

def parse_kubernetes_content_text(content_text):
    """
    Metemos regex por posibles cambios de futuro en la API, ya que aunque tirar de regex consume un poco mas de procesamiento
    nos ahorramos el tener problemas a futuro, ademas, al ser un regex sencillo no dara ningun tipo de problema.
    """
    score = 0.0
    score_match = re.search(r"Score:\s*(\d{1,2}\.\d)", content_text, re.IGNORECASE)
    if score_match:
        try: score = float(score_match.group(1))
        except ValueError: logging.warning(f"No se pudo convertir score a float: {score_match.group(1)}")
    return score, "N/A"

def fetch_kubernetes_vulnerabilities(start_date_utc_naive):
    logging.info(f"Consultando Kubernetes CVE Feed: {KUBERNETES_CVE_FEED_URL}")
    logging.info("Seleccionando los 2 CVEs más recientes de Kubernetes.")
    try:
        resp = requests.get(KUBERNETES_CVE_FEED_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        all_items = data.get("items", [])
        logging.info(f"Kubernetes Feed devolvió {len(all_items)} items en total.")

        valid_items_with_dates = []
        for item_idx, item in enumerate(all_items):
            published_str = item.get("date_published", "").rstrip("Z")
            if not published_str:
                logging.warning(f"Item de Kubernetes (idx {item_idx}) sin 'date_published': {item.get('id')}")
                continue
            try:
                item_published_date_aware = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                item_published_date_naive_utc = item_published_date_aware.astimezone(timezone.utc).replace(tzinfo=None)
                valid_items_with_dates.append({"item_data": item, "published_date": item_published_date_naive_utc})
            except ValueError as e:
                logging.error(f"Error al parsear fecha para item de Kubernetes (idx {item_idx}, ID {item.get('id')}): {item.get('date_published')} - {e}")

        valid_items_with_dates.sort(key=lambda x: x["published_date"], reverse=True)

        recent_items_data = [entry["item_data"] for entry in valid_items_with_dates[:2]]

        logging.info(f"Kubernetes Feed: {len(recent_items_data)} items seleccionados (los 2 más recientes).")
        return recent_items_data
    except (requests.exceptions.RequestException, ValueError) as e:
        logging.error(f"Error Kubernetes CVE Feed: {e}")
    return []

def process_kubernetes_vulnerabilities(last_check_time, processed_ids):
    logging.info("Procesando Kubernetes CVEs con deduplicación.")
    kubernetes_items = fetch_kubernetes_vulnerabilities(last_check_time)

    if not kubernetes_items:
        logging.info("No se encontraron vulnerabilidades de Kubernetes para procesar.")
        return 0, 0

    count_sent = 0
    critical_found_count = 0

    for item in kubernetes_items:
        cve_id = item.get("id")
        if not cve_id or cve_id in processed_ids:
            continue

        description = item.get("summary", "No descripción.")
        score, _ = parse_kubernetes_content_text(item.get("content_text", ""))
        if score >= 9.0:
            critical_found_count += 1

        published_date_str = item.get("date_published", "N/A").split("T")[0]
        details_url = item.get("external_url", item.get("url", "#"))

        if post_to_teams(
            cve_id,
            f"Vulnerabilidad Kubernetes: {cve_id}",
            description,
            score,
            details_url,
            SOURCE_KUBERNETES,
            published_date_str
        ):
            count_sent += 1

        # Marcamos este CVE como procesado para no reenviarlo
        processed_ids.add(cve_id)

    logging.info(f"Kubernetes: enviadas={count_sent}, críticas nuevas={critical_found_count}.")
    return count_sent, critical_found_count

def process_redhat_vulnerabilities(last_check_time, processed_ids):
    logging.info("Procesando Red Hat CVEs con deduplicación.")
    # Usamos un rango amplio para luego quedarnos con los 2 más recientes
    ninety_days_ago = datetime.utcnow() - timedelta(days=90)
    rh_items_all = fetch_redhat_vulnerabilities(ninety_days_ago)

    # Filtrar y ordenar por fecha de publicación
    valid = []
    for item in rh_items_all:
        pub = item.get("public_date")
        if not pub:
            continue
        try:
            dt = datetime.fromisoformat(pub.replace('Z', '+00:00'))
            valid.append((dt, item))
        except ValueError:
            continue
    valid.sort(key=lambda x: x[0], reverse=True)
    recent_items = [itm for _, itm in valid[:2]]

    if not recent_items:
        logging.info("No se encontraron vulnerabilidades de Red Hat para procesar.")
        return 0, 0

    count_sent = 0
    critical_found_count = 0

    for item in recent_items:
        cve_id = item.get("CVE")
        if not cve_id or cve_id in processed_ids:
            continue

        description = item.get("bugzilla_description", item.get("description", "No descripción."))
        try:
            score = float(item.get("cvss3_score", 0.0))
        except (ValueError, TypeError):
            score = 0.0
        if score >= 9.0:
            critical_found_count += 1

        published_date_str = item.get("public_date", "N/A").split("T")[0]
        details_url = item.get("resource_url", f"https://access.redhat.com/security/cve/{cve_id}")

        if post_to_teams(
            cve_id,
            f"Vulnerabilidad OpenShift: {cve_id}",
            description,
            score,
            details_url,
            SOURCE_REDHAT,
            published_date_str
        ):
            count_sent += 1

        # Marcamos este CVE como procesado para no reenviarlo
        processed_ids.add(cve_id)

    logging.info(f"Red Hat: enviadas={count_sent}, críticas nuevas={critical_found_count}.")
    return count_sent, critical_found_count

# ----------------------------------
# Arranque y bucle principal
# ----------------------------------

if __name__ == "__main__":
    # 1) Carga timestamp e IDs ya procesados
    last_check_time, processed_ids = load_last_run_state(STATE_FILE)

    # 2) Inicia servidor de métricas
    try:
        start_http_server(METRICS_PORT)
        logging.info(f"Servidor de métricas Prometheus iniciado en el puerto {METRICS_PORT}.")
    except Exception as e_metrics:
        logging.error(f"No se pudo iniciar el servidor de métricas en el puerto {METRICS_PORT}: {e_metrics}")
        exit(1)

    intervalo_segundos = 5 * 60  # 5 minutos

    # 3) Bucle infinito
    while True:
        now_utc = datetime.utcnow().replace(tzinfo=timezone.utc).replace(tzinfo=None)
        logging.info(f"--- Iniciando ciclo a las {now_utc.isoformat()}Z ---")

        try:
            # Ejecuta el trabajo y actualiza métricas
            k8s_sent, k8s_crit = process_kubernetes_vulnerabilities(last_check_time, processed_ids)
            rh_sent,  rh_crit  = process_redhat_vulnerabilities (last_check_time, processed_ids)

            cve_critical_total.labels(source=SOURCE_KUBERNETES).set(k8s_crit)
            cve_critical_total.labels(source=SOURCE_REDHAT)    .set(rh_crit)

            # Actualiza último timestamp y guarda el estado completo
            last_check_time = now_utc
            save_last_run_state(STATE_FILE, last_check_time, processed_ids)

            logging.info(f"Ciclo completado. Enviadas: K8s={k8s_sent}, RH={rh_sent}.")
        except Exception as e:
            logging.error(f"Error en ciclo principal: {e}", exc_info=True)

        logging.info(f"Esperando {intervalo_segundos}s hasta la siguiente ejecución...")
        time.sleep(intervalo_segundos)