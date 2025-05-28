#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="vuln_reporter:1.0"
NAMESPACE="monitoring"

echo "🔨 Construyendo la imagen Docker: $IMAGE_NAME"
minikube image build -t "$IMAGE_NAME" .

echo "🚀 Desplegando Secret y Deployment en Kubernetes"
kubectl apply -f teams-webhook-secret.yaml
kubectl apply -f deployment.yaml

# Instala Helm si no existe
if ! command -v helm &> /dev/null; then
  echo "📦 Helm no encontrado. Instalando Helm 3..."
  curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
  chmod +x get_helm.sh
  ./get_helm.sh
  rm get_helm.sh
fi

echo "📝 Configurando repositorios Helm"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

echo "📈 Desplegando Prometheus"
helm upgrade --install prometheus prometheus-community/prometheus \
  -n $NAMESPACE --create-namespace \
  -f values.yaml

echo "📊 Desplegando Grafana"
helm upgrade --install grafana grafana/grafana \
  -n $NAMESPACE --reuse-values || true

echo "⏳ Esperando a que los Deployments estén Ready…"
kubectl -n $NAMESPACE rollout status deployment/prometheus-server --timeout=120s
kubectl -n $NAMESPACE rollout status deployment/grafana --timeout=120s

echo "✅ Deployments listos. Iniciando port-forwards…"
kubectl -n $NAMESPACE port-forward deploy/prometheus-server 9090:9090 &
PROM_FWD_PID=$!
kubectl -n $NAMESPACE port-forward deploy/grafana 3000:3000 &
GRAF_FWD_PID=$!

# Obtener credencial de Grafana
echo "🔑 Obteniendo contraseña de Grafana desde el Secret..."
GRAFANA_PASS=$(kubectl get secret -n $NAMESPACE grafana -o jsonpath="{.data.admin-password}" | base64 --decode)

# Esperar a que la API de Grafana responda
echo "⏳ Esperando a que Grafana API esté disponible en http://localhost:3000…"
until curl -s -u admin:$GRAFANA_PASS http://localhost:3000/api/health | grep -q '"database"'; do
  sleep 2
done
echo "✅ Grafana API lista."

# Crear datasource apuntando a Prometheus
echo "🔗 Creando datasource en Grafana para Prometheus…"
curl -s -X POST http://localhost:3000/api/datasources \
  -H "Content-Type: application/json" \
  -u admin:$GRAFANA_PASS \
  -d '{
    "name": "Prometheus",
    "type": "prometheus",
    "access": "proxy",
    "url": "http://prometheus-server.'$NAMESPACE'.svc.cluster.local:80",
    "isDefault": true
  }' >/dev/null

cat <<EOF
✔️ Despliegue completado y datasource configurado.

📋 Credenciales de acceso a Grafana:
  User: admin
  Pass: $GRAFANA_PASS

🔍 Puedes abrir en tu navegador:
   • Prometheus → http://localhost:9090
   • Grafana    → http://localhost:3000

Para detener los port-forwards, pulsa Ctrl+C o mata estos PIDs:
  Prometheus PID: $PROM_FWD_PID
  Grafana    PID: $GRAF_FWD_PID
EOF

# Mantener el script en primer plano para que los port-forwards sigan activos
trap "echo '🛑 Parando port-forwards…'; kill $PROM_FWD_PID $GRAF_FWD_PID; exit 0" SIGINT SIGTERM
wait
