#include "suricata-common.h"
#include "util-wasm-tls.h"

#ifdef HAVE_WASM

#include "app-layer-ssl.h"

int32_t _wasm_tls_get_serial(const Flow *f, const char **result) {
    void *state = FlowGetAppState(f);
    if (state == NULL) {
        *result = "error: no app layer state";
        return -1;
    }

    SSLState *ssl_state = (SSLState *)state;

    *result = ssl_state->server_connp.cert0_serial;
    return 0;
}

int32_t _wasm_tls_get_sni(const Flow *f, const char **result) {
    void *state = FlowGetAppState(f);
    if (state == NULL) {
        *result = "error: no app layer state";
        return -1;
    }

    SSLState *ssl_state = (SSLState *)state;

    *result = ssl_state->client_connp.sni;
    return 0;
}

#endif /* HAVE_WASM */
