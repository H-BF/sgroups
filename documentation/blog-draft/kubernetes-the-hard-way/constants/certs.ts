import { TCertsItems }    from '../customTypes/certs'

export const CERTIFICATES: TCertsItems = {
  etcdCA: {
    keyPath: "${BASE_K8S_PATH}/pki/etcd/ca.key",
    crtPath: "${BASE_K8S_PATH}/pki/etcd/ca.crt", 
    csrPath: "",
    crtConf: "${BASE_K8S_PATH}/openssl/etcd-ca.conf",
    keySize: "2048"
  },
  kubernetesCA: {
    keyPath: "${BASE_K8S_PATH}/pki/ca.key",
    crtPath: "${BASE_K8S_PATH}/pki/ca.crt", 
    csrPath: "",
    crtConf: "${BASE_K8S_PATH}/openssl/ca.conf",
    keySize: "2048"
  },
  frontProxyCA: {
    keyPath: "${BASE_K8S_PATH}/pki/front-proxy-ca.key",
    crtPath: "${BASE_K8S_PATH}/pki/front-proxy-ca.crt", 
    csrPath: "",
    crtConf: "${BASE_K8S_PATH}/openssl/front-proxy-ca.conf",
    keySize: "2048"
  },
  controllerManagerClient: {
    keyPath: "${BASE_K8S_PATH}/kubeconfig/controller-manager-client-key.pem",
    crtPath: "${BASE_K8S_PATH}/kubeconfig/controller-manager-client.pem", 
    csrPath: "${BASE_K8S_PATH}/openssl/csr/controller-manager-client.csr",
    crtConf: "${BASE_K8S_PATH}/openssl/controller-manager-client.conf",
    keySize: "2048"
  },
  etcdClient: {
    keyPath: "${BASE_K8S_PATH}/pki/etcd/healthcheck-client.key",
    crtPath: "${BASE_K8S_PATH}/pki/etcd/healthcheck-client.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/healthcheck-client.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/etcd-client.csr",
    keySize: "2048"
  },
  etcdServer: {
    keyPath: "${BASE_K8S_PATH}/pki/etcd/server.key",
    crtPath: "${BASE_K8S_PATH}/pki/etcd/server.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/etcd-server.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/etcd-server.csr",
    keySize: "2048"
  },
  etcdPeer: {
    keyPath: "${BASE_K8S_PATH}/pki/etcd/peer.key",
    crtPath: "${BASE_K8S_PATH}/pki/etcd/peer.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/etcd-peer.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/etcd-peer.csr",
    keySize: "2048"
  },
  kubernetesKubeletClient: {
    keyPath: "${BASE_K8S_PATH}/pki/apiserver-kubelet-client.key",
    crtPath: "${BASE_K8S_PATH}/pki/apiserver-kubelet-client.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/apiserver-kubelet-client.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/apiserver-kubelet-client.csr",
    keySize: "2048"
  },
  kubernetesFrontProxyClient: {
    keyPath: "${BASE_K8S_PATH}/pki/front-proxy-client.key",
    crtPath: "${BASE_K8S_PATH}/pki/front-proxy-client.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/front-proxy-client.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/front-proxy-client.csr",
    keySize: "2048"
  },
  kubernetesEtcdClient: {
    keyPath: "${BASE_K8S_PATH}/pki/apiserver-etcd-client.key",
    crtPath: "${BASE_K8S_PATH}/pki/apiserver-etcd-client.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/apiserver-etcd-client.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/apiserver-etcd-client.csr",
    keySize: "2048"
  },
  kubernetesServer: {
    keyPath: "${BASE_K8S_PATH}/pki/apiserver.key",
    crtPath: "${BASE_K8S_PATH}/pki/apiserver.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/apiserver.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/apiserver.csr",
    keySize: "2048"
  },
  kubernetesSuperAdminClient: {
    keyPath: "${BASE_K8S_PATH}/kubeconfig/super-admin.key",
    crtPath: "${BASE_K8S_PATH}/kubeconfig/super-admin.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/super-admin.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/super-admin.csr",
    keySize: "2048"
  },
  kubernetesAdminClient: {
    keyPath: "${BASE_K8S_PATH}/kubeconfig/admin.key",
    crtPath: "${BASE_K8S_PATH}/kubeconfig/admin.crt", 
    csrPath: "${BASE_K8S_PATH}/openssl/admin.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/admin.csr",
    keySize: "2048"
  },
  kubernetesSA: {
    keyPath: "${BASE_K8S_PATH}/pki/sa.key",
    crtPath: "${BASE_K8S_PATH}/pki/sa.pub", 
    csrPath: "",
    crtConf: "",
    keySize: "2048"
  },
  kubernetesScheduler: {
    keyPath: "${BASE_K8S_PATH}/pki/sa.key",
    crtPath: "${BASE_K8S_PATH}/pki/sa.pub", 
    csrPath: "",
    crtConf: "",
    keySize: "2048"
  },
  kubeletClient: {
    keyPath: "${BASE_K8S_PATH}/pki/kubelet-client-key.pem",
    crtPath: "${BASE_K8S_PATH}/pki/kubelet-client.pem", 
    csrPath: "${BASE_K8S_PATH}/openssl/kubelet-client.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/kubelet-client.csr",
    keySize: "2048"
  },
  kubeletServer: {
    keyPath: "${BASE_K8S_PATH}/pki/kubelet-server-key.pem",
    crtPath: "${BASE_K8S_PATH}/pki/kubelet-server.pem", 
    csrPath: "${BASE_K8S_PATH}/openssl/kubelet-server.conf",
    crtConf: "${BASE_K8S_PATH}/openssl/csr/kubelet-server.csr",
    keySize: "2048"
  },
  kubernetesCureentClient: {
    keyPath: "",
    crtPath: "${BASE_KUBELET_PATH}/pki/kubelet-client-current.pem",
    csrPath: "",
    crtConf: "",
    keySize: "2048"
  },
  kubernetesCureentServer: {
    keyPath: "",
    crtPath: "${BASE_KUBELET_PATH}/pki/kubelet-server-current.pem",
    csrPath: "",
    crtConf: "",
    keySize: "2048"
  },
}
