#include <libssh/libssh.h>

void start_ssh_server(int port) {
    ssh_bind bind = ssh_bind_new();
    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_listen(bind, port);
    ssh_bind_accept(bind, NULL);
}
