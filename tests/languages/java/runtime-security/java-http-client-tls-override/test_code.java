package javahttpclienttlsoverride;

import java.net.http.HttpClient;
import okhttp3.OkHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

public class TestCode {
    public void customClients(javax.net.ssl.SSLSocketFactory factory, javax.net.ssl.X509TrustManager trust) {
        OkHttpClient ok = new OkHttpClient.Builder()
            .sslSocketFactory(factory, trust)
            .build();
        HttpClient jdk = HttpClient.newBuilder().build();
        HttpClients.custom().build();
        RestTemplate rest = new RestTemplate(new HttpComponentsClientHttpRequestFactory());
    }
}
