package javapqchardcodedcipherdependencies;

import javax.net.ssl.SSLContext;

public class NegativeCases {
    public SSLContext defaultContext() throws Exception {
        return SSLContext.getInstance("Default");
    }
}
