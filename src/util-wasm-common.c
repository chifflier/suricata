#include "suricata-common.h"
#include "util-wasm-common.h"

AppProto wasm_get_flow_app_proto(Flow *f) {
    return f->alproto;
}

const char *wasm_app_proto_to_string(const AppProto alproto) {
    const char *s = AppProtoToString(alproto);
    if (s != NULL) {
        return s;
    } else {
        return "unknown";
    }
}

void wasm_packet_timestamp(const Packet *p, uint64_t *sec, uint64_t *usec) {
    if (p != NULL) {
        *sec = p->ts.tv_sec;
        *usec = p->ts.tv_usec;
    }
}
