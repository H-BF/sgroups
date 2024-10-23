import { TCustomValueItems } from '../customTypes/customValue'


export const CUSTOM_VALUE: TCustomValueItems = {
  baseDockerRegistry: {
    value: 'registry.k8s.io'
  },
  pausedImage: {
    value: "pause:3.9"
  },
  kubernetesBaseDomain: {
    value: "prorobotech.ru"
  },
  kubernetesClusterName: {
    value: "example"
  },
  kuberneteBaseFolderPath: {
    value: "/etc/kubernetes"
  },
  kuberneteKubeletFolderPath: {
    value: "/var/lib/kubelet"
  },
  criEndpoint: {
    value: "/var/run/containerd/containerd.sock"
  },
  kubernetesServiceCIDR: {
    value: "29.64.0.0/16"
  },
  kubernetesDNSAddress: {
    value: "29.64.0.10"
  },
  kubernetesDefaultInternalAddress: {
    value: "29.64.0.1"
  },
  virtualMachineLocalAddress: {
    value: "$(ip -4 addr show scope global | awk '/inet/ {print $2; exit}' | cut -d/ -f1)"
  },


}
