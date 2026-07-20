#include <libssh/libssh.h>

void ssh_connect_client(const char *host) {
    ssh_session session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_connect(session);
    ssh_userauth_publickey_auto(session, NULL, NULL);
}

void ssh_password_auth(ssh_session session, const char *user, const char *pass) {
    ssh_userauth_password(session, user, pass);
}
