#!/usr/bin/env bash

BASE_DIR="/media/palantir-nfs/ti-mmml-tc"
IDS_parser_DIR="${BASE_DIR}/k8s/IDS_parser/ids_parser_docker"

echo "Rebuilding IDS_parser docker image..."
cd ${IDS_parser_DIR} && docker build -t palantir-ids-parser:1.0 . && docker tag palantir-ids-parser:1.0 10.101.10.244:5000/palantir-ids-parser:1.0 && docker push 10.101.10.244:5000/palantir-ids-parser:1.0
if [[ $(kubectl get pods --all-namespaces | grep ids-parser | wc -l) -gt 0 ]]; then
  echo "Existing IDS_parser pod found, deleting..."
  kubectl delete pod ids-parser
fi

echo "Creating IDS_parser pod"
kubectl create -f ${IDS_parser_DIR}/pod.yaml

echo "Waiting for IDS_parser pod startup"
while [[ $(kubectl get pods --all-namespaces | grep ids-parser | grep Running | wc -l) -eq 0 ]]; do
  echo -n "."
done
echo
echo "IDS_parser pod started, attaching..."
kubectl logs ids-parser && kubectl attach ids-parser
