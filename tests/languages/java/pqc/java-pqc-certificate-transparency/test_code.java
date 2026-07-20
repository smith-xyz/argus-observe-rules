package javapqccertificatetransparency;

import java.security.cert.X509Certificate;
import org.certificatetransparency.ctlog.CTLogClient;

public class TestCode {
    public byte[] readSctExtension(X509Certificate cert) {
        return cert.getExtensionValue("1.3.6.1.4.1.11129.2.4.2");
    }

    public void queryCtLog(String url) throws Exception {
        CTLogClient client = new CTLogClient(url);
        client.getSignedTreeHead();
        client.getEntries(0, 10);
        client.addCertificateChain(new byte[0]);
    }
}
