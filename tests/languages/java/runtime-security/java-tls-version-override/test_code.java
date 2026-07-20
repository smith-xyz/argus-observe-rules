package javatlsversionoverride;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class TestCode {
    public void limitTls() throws Exception {
        SSLContext tls1 = SSLContext.getInstance("TLSv1");
        SSLContext tls11 = SSLContext.getInstance("TLSv1.1");
        SSLContext tls12 = SSLContext.getInstance("TLSv1.2");
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
        System.setProperty("https.protocols", "TLSv1.2");
    }

    public void socketProtocols(SSLSocket socket) {
        socket.setEnabledProtocols(new String[] {"TLSv1.2"});
    }
}
