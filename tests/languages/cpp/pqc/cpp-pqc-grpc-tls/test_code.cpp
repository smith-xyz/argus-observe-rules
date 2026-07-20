#include <grpcpp/grpcpp.h>

void grpc_secure() {
    auto creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
    auto channel = grpc::CreateChannel("localhost:50051", creds);
    auto insecure = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
    grpc::ServerBuilder builder;
}
