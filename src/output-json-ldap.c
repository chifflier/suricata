/* Copyright (C) 2015-2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 * Implement JSON/eve logging app-layer LDAP.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-ldap.h"
#include "output-json-ldap.h"

#include "rust.h"

typedef struct LogLDAPCtx_ {
    void *rs_logger;
    OutputJsonCtx *eve_ctx;
} LogLDAPCtx;

typedef struct LogLDAPLogThread_ {
    LogLDAPCtx *ldap_ctx;
    OutputJsonThreadCtx *thread;
} LogLDAPLogThread;

static int JsonLDAPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LDAPTransaction *ldaptx = tx;
    LogLDAPLogThread *thread = thread_data;
    LogLDAPCtx *ctx = thread->ldap_ctx;

    if (!rs_ldap_logger_do_log(ctx->rs_logger, tx)) {
        return TM_ECODE_OK;
    }

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "ldap", NULL, ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "ldap");
    if (!rs_ldap_log_json_response(jb, state, ldaptx)) {
        goto error;
    }
    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread->thread);

    jb_free(jb);
    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}


static void OutputLDAPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogLDAPCtx *ldap_ctx = (LogLDAPCtx *)output_ctx->data;
    rs_dhcp_logger_free(ldap_ctx->rs_logger);
    SCFree(ldap_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputLdapLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };

    LogLDAPCtx *ldap_ctx = SCCalloc(1, sizeof(*ldap_ctx));
    if (unlikely(ldap_ctx == NULL)) {
        return result;
    }
    ldap_ctx->eve_ctx = parent_ctx->data;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ldap_ctx);
        return result;
    }
    output_ctx->data = ldap_ctx;
    output_ctx->DeInit = OutputLDAPLogDeInitCtxSub;

    ldap_ctx->rs_logger = rs_ldap_logger_new(conf);

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_LDAP);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_LDAP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonLDAPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogLDAPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }
    LogLDAPCtx *ctx = ((OutputCtx *)initdata)->data;
    thread->ldap_ctx = ctx;
    thread->thread = CreateEveThreadCtx(t, ctx->eve_ctx);
    if (thread->thread == NULL) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    *data = (void *)thread;
    return TM_ECODE_OK;
}

static TmEcode JsonLDAPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogLDAPLogThread *thread = (LogLDAPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->thread);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonLdapLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonLdapLog", "eve-log.ldap",
        OutputLdapLogInitSub, ALPROTO_LDAP, JsonLDAPLogger, JsonLDAPLogThreadInit,
        JsonLDAPLogThreadDeinit, NULL);

    SCLogNotice("Ldap JSON logger registered.");
}
