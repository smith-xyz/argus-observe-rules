async fn mesh_bypass(service_ip: &str, port: u16) {
    let url = format!("http://{}:{}", service_ip, port);
    let _ = reqwest::get(&url).await;
}

async fn endpoint_bypass(endpoint: &str) {
    let url = format!("http://{}", endpoint);
    let _ = reqwest::get(&url).await;
}
