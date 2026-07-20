package javapqcgrpctls;

import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.Grpc;
import io.grpc.ServerBuilder;
import io.netty.handler.ssl.SslContext;

public class TestCode {
    public io.grpc.ManagedChannel secureChannel(String host, int port, SslContext sslContext) {
        return NettyChannelBuilder.forAddress(host, port)
            .sslContext(sslContext)
            .build();
    }

    public io.grpc.ManagedChannel transportSecurity(String host, int port) {
        return ManagedChannelBuilder.forAddress(host, port)
            .useTransportSecurity()
            .build();
    }

    public io.grpc.ManagedChannel grpcBuilder(String target, io.grpc.ChannelCredentials creds) {
        return Grpc.newChannelBuilder(target, creds).build();
    }

    public io.grpc.Server grpcServer(int port) {
        return ServerBuilder.forPort(port).build();
    }
}
