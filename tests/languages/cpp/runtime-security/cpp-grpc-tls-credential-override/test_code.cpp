#include <grpcpp/grpcpp.h>

void insecure_grpc() {
    auto channel = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
    auto creds = grpc::experimental::LocalCredentials(grpc_local_connect_type::LOCAL_TCP);
}
