package javatlsbypass;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.OkHttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;

public class TestCode {
    public void bypassHostnameVerifier() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    public SSLContext bypassSslContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new java.security.SecureRandom());
        return context;
    }

    public OkHttpClient bypassOkHttp() {
        return new OkHttpClient.Builder()
            .hostnameVerifier((hostname, session) -> true)
            .build();
    }

    public void apacheBypass() {
        NoopHostnameVerifier.INSTANCE.verify("host", null);
        TrustAllStrategy.INSTANCE;
    }
}
