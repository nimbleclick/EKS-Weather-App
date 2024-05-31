#!/bin/bash

# set the kubeconfig file
aws eks update-kubeconfig --region us-east-1 --name EKS-Cluster

# install eksctl
ARCH=amd64
PLATFORM=$(uname -s)_$ARCH
curl -sLO "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_$PLATFORM.tar.gz"
curl -sL "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_checksums.txt" | grep $PLATFORM | sha256sum --check
tar -xzf eksctl_$PLATFORM.tar.gz -C /tmp && rm eksctl_$PLATFORM.tar.gz
sudo mv /tmp/eksctl /usr/local/bin


# install helm
curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 > get_helm.sh
chmod 700 get_helm.sh
./get_helm.sh

# install the secrets store csi driver
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install -n kube-system csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver

# install the aws secrets store csi driver provider (ASCP)
kubectl apply -f https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml

# update the clusterrole "secretproviderclasses-role" with permissions to create/get/list/watch secrets
kubectl replace --force -f secretproviderclasses-role.yaml
sleep 5

# create the app infrastructure
kubectl apply -f k8s-infrastructure.yaml
sleep 10

#install the aws load balancer controller
helm repo add eks https://aws.github.io/eks-charts
helm repo update eks
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=EKS-Cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
sleep 25
kubectl get deployment -n kube-system aws-load-balancer-controller