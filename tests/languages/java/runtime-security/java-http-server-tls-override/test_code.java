package javahttpservertlsoverride;

import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import io.grpc.netty.NettyServerBuilder;

public class TestCode {
    public void serveTls(SSLContext context, int port) throws Exception {
        SSLServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        HttpsServer server = HttpsServer.create(new java.net.InetSocketAddress(port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        NettyServerBuilder.forPort(port).sslContext(null);
    }
}
