package javatlsversionoverride;

import javax.net.ssl.SSLContext;

public class NegativeCases {
    public SSLContext modernTls() throws Exception {
        return SSLContext.getDefault();
    }
}
