#include <libssh/libssh.h>

void ssh_client(const char *host) {
    ssh_session session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_connect(session);
    ssh_userauth_publickey_auto(session, nullptr, nullptr);
}
