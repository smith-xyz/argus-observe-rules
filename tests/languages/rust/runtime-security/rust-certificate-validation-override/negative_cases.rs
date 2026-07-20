use reqwest::Client;

fn secure_client() -> Client {
    Client::builder().build().unwrap()
}
