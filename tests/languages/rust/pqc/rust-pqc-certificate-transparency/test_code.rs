use ct_client::LogClient;
use sct;

fn query_ct_log(url: &str) {
    let client = LogClient::new(url.to_string());
    let _sth = client.get_sth();
    let _entries = client.get_entries(0, 10);
}

fn submit_chain(client: &LogClient, chain: &[u8]) {
    let _ = client.add_chain(chain);
}

fn verify_sct(cert: &[u8], logs: &[sct::Log], timestamp: u64) {
    let _ = sct::verify_sct(cert, logs, timestamp);
}
