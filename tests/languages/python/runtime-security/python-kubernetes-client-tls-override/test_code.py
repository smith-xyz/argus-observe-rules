from kubernetes import client, config

def k8s_insecure():
    config.load_kube_config()
    configuration = client.Configuration()
    configuration.verify_ssl = False
    configuration.assert_hostname = False
    return configuration
