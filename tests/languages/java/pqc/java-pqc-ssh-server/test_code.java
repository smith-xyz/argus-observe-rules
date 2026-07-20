package javapqcsshserver;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.common.keyprovider.KeyPairProvider;

public class TestCode {
    public SshServer startSshServer(String host, int port, KeyPairProvider provider) throws Exception {
        SshServer server = SshServer.setUpDefaultServer();
        server.setHost(host);
        server.setPort(port);
        server.setKeyPairProvider(provider);
        server.start();
        return server;
    }
}
