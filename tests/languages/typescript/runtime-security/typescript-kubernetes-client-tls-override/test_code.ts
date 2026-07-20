import k8s from '@kubernetes/client-node';

function k8sInsecure() {
  const kc = new k8s.KubeConfig();
  kc.loadFromDefault();
  kc.loadFromCluster();
  const cluster = { skipTLSVerify: true };
  return { kc, cluster };
}
