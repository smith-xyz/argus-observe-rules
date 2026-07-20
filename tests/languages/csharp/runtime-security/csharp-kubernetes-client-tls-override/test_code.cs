using System;
using k8s;

namespace CSharpKubernetesClientTlsOverride
{
    class Program
    {
        static void K8sInsecure()
        {
            var config = KubernetesClientConfiguration.BuildConfigFromConfigFile();
            config.SkipTlsVerify = true;
            var inCluster = KubernetesClientConfiguration.IsInCluster();
            var fresh = new KubernetesClientConfiguration();
        }
    }
}
