#include <libssh/libssh.h>

void ssh_server(int port) {
    ssh_bind bind = ssh_bind_new();
    ssh_bind_listen(bind, port);
    ssh_bind_accept(bind, nullptr);
}
