use reqwest::Client;
use ureq::AgentBuilder;

fn custom_clients() {
    let _client = reqwest::Client::builder().build().unwrap();
    let _builder = reqwest::ClientBuilder::new();
    let _agent = AgentBuilder::new().build();
    let _isahc = isahc::HttpClient::builder().build().unwrap();
}
