# Kubernetes and Helm Resources

provider "kubectl" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

resource "kubernetes_namespace" "aegisgraph" {
  metadata {
    name = "aegisgraph"
  }
}

# Ingress Controller (NGINX)
resource "helm_release" "nginx_ingress" {
  name       = "nginx-ingress"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  namespace  = "kube-system"

  set {
    name  = "controller.service.type"
    value = "LoadBalancer"
  }
}

# Apply Neo4j Manifest
data "kubectl_path_documents" "neo4j" {
  pattern = "${path.module}/../kubernetes/neo4j-statefulset.yaml"
}

resource "kubectl_manifest" "neo4j" {
  for_each  = data.kubectl_path_documents.neo4j.manifests
  yaml_body = each.value
  depends_on = [kubernetes_namespace.aegisgraph]
}

data "kubectl_path_documents" "kafka" {
  pattern = "${path.module}/../kubernetes/kafka-statefulset.yaml"
}

resource "kubectl_manifest" "kafka" {
  for_each  = data.kubectl_path_documents.kafka.manifests
  yaml_body = each.value
  depends_on = [kubernetes_namespace.aegisgraph]
}

data "kubectl_path_documents" "redis" {
  pattern = "${path.module}/../kubernetes/redis-statefulset.yaml"
}

resource "kubectl_manifest" "redis" {
  for_each  = data.kubectl_path_documents.redis.manifests
  yaml_body = each.value
  depends_on = [kubernetes_namespace.aegisgraph]
}

data "kubectl_path_documents" "postgresql" {
  pattern = "${path.module}/../kubernetes/postgresql-statefulset.yaml"
}

resource "kubectl_manifest" "postgresql" {
  for_each  = data.kubectl_path_documents.postgresql.manifests
  yaml_body = each.value
  depends_on = [kubernetes_namespace.aegisgraph]
}

data "kubectl_path_documents" "deployment" {
  pattern = "${path.module}/../kubernetes/deployment.yaml"
}

resource "kubectl_manifest" "deployment" {
  for_each  = data.kubectl_path_documents.deployment.manifests
  yaml_body = each.value
  depends_on = [kubernetes_namespace.aegisgraph]
}
