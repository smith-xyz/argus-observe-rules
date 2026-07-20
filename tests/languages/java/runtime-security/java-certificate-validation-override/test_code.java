package javacertificatevalidationoverride;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class TestCode {
    public void overrideValidation() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        HostnameVerifier verifier = new HostnameVerifier() {
            public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
                return true;
            }
        };

        CloseableHttpClient client = HttpClients.custom()
            .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
            .build();
    }
}
