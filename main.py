from datetime import datetime, timedelta, timezone
import time
import logging
import requests
import configparser
import re
import json
from prometheus_client import start_http_server, Gauge

LAST_SUCCESSFUL_RUN_TIME_FILE = "last_run_state.json"
CONFIG_FILE = 'config.cfg'
PLACEHOLDER_WEBHOOK_VALUE = "WEBHOOK_NO_CONFIGURADO"
DEFAULT_METRICS_PORT = 8000

config = configparser.ConfigParser()
TEAMS_WEBHOOK = PLACEHOLDER_WEBHOOK_VALUE
METRICS_PORT = DEFAULT_METRICS_PORT

try:
    files_read = config.read(CONFIG_FILE)
    if not files_read:
        logging.warning(f"Archivo de configuración '{CONFIG_FILE}' no encontrado o no se pudo leer. Se usarán valores por defecto/placeholders. Por favor, crea y configura '{CONFIG_FILE}'.")
    else:
        logging.info(f"Archivo de configuración '{CONFIG_FILE}' leído exitosamente.")
        retrieved_webhook = config.get('webhook', 'webhook_url', fallback=PLACEHOLDER_WEBHOOK_VALUE)
        if retrieved_webhook and retrieved_webhook.strip() and retrieved_webhook != PLACEHOLDER_WEBHOOK_VALUE:
            TEAMS_WEBHOOK = retrieved_webhook
        else:
            TEAMS_WEBHOOK = PLACEHOLDER_WEBHOOK_VALUE
            if retrieved_webhook != PLACEHOLDER_WEBHOOK_VALUE:
                logging.warning(f"La clave 'webhook_url' en '{CONFIG_FILE}' está vacía o no se encontró. Usando placeholder.")

except configparser.Error as e_cfg_parser:
    logging.error(f"Error al parsear el archivo de configuración '{CONFIG_FILE}': {e_cfg_parser}. Se usarán valores por defecto/placeholders.")
    TEAMS_WEBHOOK = PLACEHOLDER_WEBHOOK_VALUE
    METRICS_PORT = DEFAULT_METRICS_PORT
    
except Exception as e_config:
    logging.error(f"Error inesperado al leer o procesar el archivo de configuración '{CONFIG_FILE}': {e_config}. Se usarán valores por defecto/placeholders.")
    TEAMS_WEBHOOK = PLACEHOLDER_WEBHOOK_VALUE
    METRICS_PORT = DEFAULT_METRICS_PORT

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
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            last_time_str = data.get("last_check_time_utc_iso")
            if last_time_str:
                dt_aware = datetime.fromisoformat(last_time_str.replace('Z', '+00:00'))
                return dt_aware.astimezone(timezone.utc).replace(tzinfo=None)
    except FileNotFoundError:
        logging.info(f"Archivo '{filename}' no encontrado. Usando delta por defecto.")
    except (json.JSONDecodeError, Exception) as e:
        logging.warning(f"Error al cargar estado de '{filename}': {e}. Usando delta por defecto.")
    return datetime.utcnow() - timedelta(hours=default_timedelta_hours)

def save_last_run_state(filename, time_to_save_utc):
    try:
        with open(filename, 'w') as f:
            data = {"last_check_time_utc_iso": time_to_save_utc.isoformat() + "Z"}
            json.dump(data, f, indent=2)
        logging.info(f"Estado guardado en '{filename}'.")
    except Exception as e:
        logging.error(f"Error al guardar estado en '{filename}': {e}")

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

    if not TEAMS_WEBHOOK or TEAMS_WEBHOOK == PLACEHOLDER_WEBHOOK_VALUE:
        logging.error(f"TEAMS_WEBHOOK no configurado en '{CONFIG_FILE}'.")
        return False
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

def process_kubernetes_vulnerabilities():
    logging.info(f"Procesando Kubernetes CVEs - 2 MÁS RECIENTES")
    kubernetes_items = fetch_kubernetes_vulnerabilities(last_check_time) 

    if not kubernetes_items:
        logging.info("No se encontraron vulnerabilidades de Kubernetes para procesar (2 más recientes).")
        return 0, 0

    count_sent = 0
    critical_found_count = 0
    for item in kubernetes_items:
        cve_id = item.get("id")
        if not cve_id: continue
        description = item.get("summary", "No descripción.")
        score, _ = parse_kubernetes_content_text(item.get("content_text", ""))
        if score >= 9.0:
            critical_found_count += 1
        published_date_str = item.get("date_published", "N/A").split("T")[0]
        details_url = item.get("external_url", item.get("url", "#"))
        if post_to_teams(cve_id, f"Vulnerabilidad Kubernetes: {cve_id}", description, score, details_url, SOURCE_KUBERNETES, published_date_str):
            count_sent += 1
    logging.info(f"Kubernetes: {count_sent} alertas enviadas de {len(kubernetes_items)} (2 más recientes). Críticas encontradas: {critical_found_count}.")
    return count_sent, critical_found_count

def process_redhat_vulnerabilities():
    logging.info(f"Procesando Red Hat CVEs - 2 MÁS RECIENTES")
    ninety_days_ago = datetime.utcnow() - timedelta(days=90)
    logging.info(f"2 MÁS RECIENTES: Consultando Red Hat API con 'after={ninety_days_ago.strftime('%Y-%m-%d')}' para obtener un conjunto amplio.")
    rh_items_all = fetch_redhat_vulnerabilities(ninety_days_ago)
    
    logging.info(f"Red Hat API devolvió {len(rh_items_all)} items (consulta amplia para test).")
    
    valid_items_with_dates = []
    for item_idx, cve_item in enumerate(rh_items_all):
        public_date_str = cve_item.get("public_date")
        if public_date_str:
            try:
                item_published_date_aware = datetime.fromisoformat(public_date_str.replace('Z', '+00:00'))
                item_published_date_naive_utc = item_published_date_aware.astimezone(timezone.utc).replace(tzinfo=None)
                valid_items_with_dates.append({"item_data": cve_item, "published_date": item_published_date_naive_utc})
            except ValueError as e:
                logging.warning(f"Error al parsear fecha Red Hat: {cve_item.get('CVE')}, {public_date_str}")
        else:
            logging.warning(f"Item de Red Hat (idx {item_idx}, CVE {cve_item.get('CVE')}) sin 'public_date'. Se omitirá para ordenamiento.")

    valid_items_with_dates.sort(key=lambda x: x["published_date"], reverse=True)
    
    items_to_process = [entry["item_data"] for entry in valid_items_with_dates[:2]]
    
    logging.info(f"Red Hat: {len(items_to_process)} items seleccionados para procesar (los 2 más recientes).")

    if not items_to_process:
        logging.info("No se encontraron vulnerabilidades de OpenShift (Red Hat) para procesar en modo '2 más recientes'.")
        return 0, 0

    count_sent = 0
    critical_found_count = 0
    for item in items_to_process:
        cve_id = item.get("CVE")
        if not cve_id: continue
        description = item.get("bugzilla_description", item.get("description", "No descripción."))
        score_str = item.get("cvss3_score")
        score = 0.0
        try: score = float(score_str) if score_str is not None else 0.0
        except (ValueError, TypeError): score = 0.0
        
        if score >= 9.0:
            critical_found_count += 1
        
        published_date_str = item.get("public_date", "N/A").split("T")[0]
        details_url = item.get("resource_url", f"https://access.redhat.com/security/cve/{cve_id}")
        if post_to_teams(cve_id, f"Vulnerabilidad OpenShift: {cve_id}", description, score, details_url, SOURCE_REDHAT, published_date_str):
            count_sent += 1
    logging.info(f"Red Hat: {count_sent} alertas enviadas de {len(items_to_process)} (2 más recientes). Críticas encontradas: {critical_found_count}.")
    return count_sent, critical_found_count

def main():
    global last_check_time
    current_run_time_utc = datetime.utcnow()
    logging.info(f"--- Iniciando ciclo (desde {last_check_time.isoformat()}Z) ---")
    
    k8s_sent, k8s_critical_found = process_kubernetes_vulnerabilities()
    rh_sent, rh_critical_found = process_redhat_vulnerabilities()
    
    cve_critical_total.labels(source=SOURCE_KUBERNETES).set(k8s_critical_found)
    cve_critical_total.labels(source=SOURCE_REDHAT).set(rh_critical_found)
    logging.info(f"Métricas de Prometheus actualizadas: K8s Críticas={k8s_critical_found}, RH Críticas={rh_critical_found}")

    logging.info(f"Ciclo completado. Enviadas: K8s={k8s_sent}, RH={rh_sent}.")
    save_last_run_state(LAST_SUCCESSFUL_RUN_TIME_FILE, current_run_time_utc)
    last_check_time = current_run_time_utc

if __name__ == "__main__":
    # Carga el último timestamp guardado (o usa el por defecto)
    last_check_time = load_last_run_state(LAST_SUCCESSFUL_RUN_TIME_FILE)
    
    # Arranca el HTTP server de prometheus_client PARALELO al bucle principal
    try:
        start_http_server(METRICS_PORT)
        logging.info(f"Servidor de métricas Prometheus iniciado en el puerto {METRICS_PORT}.")
    except Exception as e_metrics:
        logging.error(f"No se pudo iniciar el servidor de métricas en el puerto {METRICS_PORT}: {e_metrics}")
        exit(1)

    # Comprueba webhook
    if not TEAMS_WEBHOOK or TEAMS_WEBHOOK == PLACEHOLDER_WEBHOOK_VALUE:
        logging.critical(f"TEAMS_WEBHOOK no configurado en '{CONFIG_FILE}'. El script no puede enviar notificaciones. Saliendo.")
        exit(1)
    logging.info("TEAMS_WEBHOOK configurado. Notificaciones se enviarán a Teams.")

    # Bucle infinito: cada 5 minutos ejecuta main() y actualiza la métrica
    intervalo_segundos = 5 * 60  # 5 minutos

    while True:
        current_run_time_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
        logging.info(f"--- Iniciando ciclo a las {current_run_time_utc.isoformat()} ---")
        try:
            main()
            logging.info(f"Esperando {intervalo_segundos}s hasta la siguiente ejecución...")
        except Exception as e:
            logging.error(f"Error en ciclo principal: {e}", exc_info=True)
        time.sleep(intervalo_segundos)