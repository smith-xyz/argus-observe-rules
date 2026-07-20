package javacertificatevalidationoverride;

import javax.net.ssl.HttpsURLConnection;

public class NegativeCases {
    public void secureDefaults() {
        HttpsURLConnection.getDefaultHostnameVerifier();
    }
}
