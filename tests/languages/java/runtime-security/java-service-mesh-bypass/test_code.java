package javaservicemeshbypass;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class TestCode {
    public void meshBypass(HttpClient client, String serviceIp, String port) throws Exception {
        String url = "http://" + serviceIp + ":" + port;
        HttpRequest request = HttpRequest.newBuilder(java.net.URI.create(url)).build();
        java.net.http.HttpResponse.BodyHandler<String> handler = HttpResponse.BodyHandlers.ofString();
        client.send(request, handler);
    }

    public void endpointBypass(CloseableHttpClient client, String endpoint) throws Exception {
        String url = "http://" + endpoint;
        HttpGet get = new HttpGet(url);
        client.execute(get);
    }
}
