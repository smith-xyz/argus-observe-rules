package javatlsbypass;

import javax.net.ssl.SSLContext;

public class NegativeCases {
    public SSLContext secureContext() throws Exception {
        return SSLContext.getDefault();
    }
}
