package javapqcconfigprofiledependencies;

import javax.net.ssl.SSLContext;
import io.grpc.ManagedChannelBuilder;

public class TestCode {
    public void checkFips() {
        System.getenv("FIPS_MODE");
        System.getenv("JAVA_FIPS");
        System.getenv("org.bouncycastle.fips.approved_only");
    }

    public SSLContext tlsContext() throws Exception {
        return SSLContext.getInstance("TLS");
    }

    public io.grpc.ManagedChannel grpcConnect(String host, int port) {
        return ManagedChannelBuilder.forAddress(host, port).build();
    }
}
