#!/bin/bash

set -euf -o pipefail

export HELM_STABLE_REPO="https://charts.helm.sh/stable"
export PROMETHEUS_STACK="prometheus-community/kube-prometheus-stack"
export PROMETHEUS_GRAFANA="deployment/prometheus-grafana"
export GRAFANA_PORT="3000"

if ! command helm &> /dev/null
then
	echo "helm could not be found"
	exit
fi

helm repo add stable ${HELM_STABLE_REPO}
helm repo update
helm install prometheus ${PROMETHEUS_STACK}
kubectl port-forward ${PROMETHEUS_GRAFANA} ${GRAFANA_PORT}
