#include <openssl/ct.h>

void query_ct_log(void) {
    CTLOG_STORE *store = CTLOG_STORE_new();
    CTLOG_STORE_load_default_file(store, "/etc/ct/log_list.cnf");
    SCT *sct = SCT_new_from_base64("abc", NULL);
}
