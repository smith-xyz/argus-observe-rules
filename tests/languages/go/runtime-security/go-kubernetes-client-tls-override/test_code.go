package gok8stlsoverride

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func restConfigInsecureLiteral() {
	// Pattern: rest.Config with Insecure TLSClientConfig - line 10
	config := &rest.Config{
		Host: "https://kubernetes.default.svc",
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}
	_ = config
}

func httpClientForInsecure() {
	// Pattern: rest.HTTPClientFor with Insecure - line 20
	_, _ = rest.HTTPClientFor(&rest.Config{
		Host: "https://kubernetes.default.svc",
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	})
}

func buildConfigFromFlagsOverride() {
	// Pattern: BuildConfigFromFlags then Insecure override - line 31
	config, err := clientcmd.BuildConfigFromFlags("", "/path/to/kubeconfig")
	if err != nil {
		return
	}
	config.TLSClientConfig.Insecure = true
	_ = config
}

func inClusterConfigOverride() {
	// Pattern: InClusterConfig then Insecure override - line 41
	config, err := rest.InClusterConfig()
	if err != nil {
		return
	}
	config.TLSClientConfig.Insecure = true
	_ = config
}
