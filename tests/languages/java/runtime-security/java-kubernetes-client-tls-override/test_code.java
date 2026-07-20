package javakubernetesclienttlsoverride;

import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.util.Config;
import io.kubernetes.client.openapi.ApiClient;

public class TestCode {
    public ApiClient k8sInsecure() throws Exception {
        ApiClient client = Config.fromConfig("kubeconfig");
        client.setVerifyingSsl(false);
        Configuration.setDefaultApiClient(client);
        return Config.defaultClient();
    }
}
