package gok8stlsoverride

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func secureKubernetesConfig() {
	config, err := clientcmd.BuildConfigFromFlags("", "/path/to/kubeconfig")
	if err != nil {
		return
	}
	config.TLSClientConfig.Insecure = false
	_ = config
}

func secureInClusterConfig() {
	config, err := rest.InClusterConfig()
	if err != nil {
		return
	}
	_ = config.TLSClientConfig.CAFile
}
