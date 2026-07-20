package javapqchardcodedcipherdependencies;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLParameters;

public class TestCode {
    public void restrictCiphers(SSLSocket socket, SSLParameters params) {
        socket.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
        params.setCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
        socket.setEnabledProtocols(new String[] {"TLSv1.2"});
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
    }
}
