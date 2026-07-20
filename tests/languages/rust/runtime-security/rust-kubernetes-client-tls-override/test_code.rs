use kube::{Client, Config};

async fn k8s_insecure() {
    let mut config = Config::infer().await.unwrap();
    config.accept_invalid_certs = true;
    config.insecure = true;
    let _client = Client::try_default().await.unwrap();
    let _kubeconfig = kube::config::Kubeconfig::read().unwrap();
}
