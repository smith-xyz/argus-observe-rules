package javapqcsshclient;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class TestCode {
    public Session sshConnect(String host, int port, String user, String password) throws Exception {
        JSch jsch = new JSch();
        Session session = jsch.getSession(user, host, port);
        session.setPassword(password);
        session.connect();
        return session;
    }

    public void loadKey(String path, String passphrase) throws Exception {
        JSch jsch = new JSch();
        jsch.addIdentity(path);
        jsch.addIdentity(path, passphrase);
    }
}
