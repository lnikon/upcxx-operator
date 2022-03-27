# UPCXX Kubernetes Operator

## Prometheus and grafana deployment
1. Install Helm
2. `helm repo add stable https://charts.helm.sh/stable`
3. `helm repo update`
4. `helm install prometheus prometheus-community/kube-prometheus-stack`
5. `kubectl port-forward deployment/prometheus-grafana 3000`
6. Login into grafana using `127.0.0.1:3000` and `admin` and `prom-operator`

## ToDo
- ~~Create docker image for the operator. Deploy operator into kubernetes and run in in-cluster mode.~~
