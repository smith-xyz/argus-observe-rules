#include <grpc/grpc.h>
#include <grpc/grpc_security.h>

void insecure_grpc(void) {
    grpc_channel *ch = grpc_insecure_channel_create("localhost:50051", NULL, NULL);
    grpc_channel_credentials *creds = grpc_local_credentials_create();
}
