package javagrpctlscredentialoverride;

import io.grpc.ManagedChannelBuilder;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;

public class TestCode {
    public io.grpc.ManagedChannel insecureGrpc(String host, int port) {
        return ManagedChannelBuilder.forAddress(host, port).usePlaintext().build();
    }

    public io.grpc.ManagedChannel insecureBuilder(String target) {
        return Grpc.newChannelBuilder(target, InsecureChannelCredentials.create()).build();
    }

    public void plainBuilder(ManagedChannelBuilder<?> builder) {
        builder.usePlaintext();
    }
}
