#include <grpc/grpc.h>
#include <grpc/grpc_security.h>

void grpc_secure_channel(void) {
    grpc_channel_credentials *creds = grpc_ssl_credentials_create(NULL, NULL, NULL, NULL);
    grpc_channel *ch = grpc_insecure_channel_create("localhost:50051", NULL, NULL);
    grpc_server_credentials *server = grpc_server_credentials_create(creds);
}
