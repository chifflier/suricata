/* Copyright (C) 2020 Open Information Security Foundation
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
 */


#include "suricata-common.h"
#include "debug.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "output-wasm.h"

#ifdef HAVE_WASM

#include "app-layer-ssl.h"

#include "rust-bindings.h"

#define MODULE_NAME "WasmLog"

typedef struct LogWasmCtx_ {
    SCMutex m;
    WasmCtx *instance;
    int deinit_once;
} LogWasmCtx;

typedef struct LogWasmThreadCtx_ {
    LogWasmCtx *wasm_ctx;
} LogWasmThreadCtx;

static TmEcode WasmLogThreadInit(ThreadVars *t, const void *initdata, void **data);
static TmEcode WasmLogThreadDeinit(ThreadVars *t, void *data);

/** \internal
 *  \brief TX logger for wasm modules
 *
 * A single call to this function will run one module instance on a single
 * transaction.
 *
 * NOTE: The flow (f) also referenced by p->flow is locked.
 */
static int WasmTxLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogWasmThreadCtx *td = (LogWasmThreadCtx *)thread_data;

    SCMutexLock(&td->wasm_ctx->m);

    // LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    // LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    // LuaStateSetTX(td->lua_ctx->luastate, txptr);
    // LuaStateSetFlow(td->lua_ctx->luastate, f);

    // /* prepare data to pass to script */
    // lua_getglobal(td->lua_ctx->luastate, "log");
    // lua_newtable(td->lua_ctx->luastate);
    // LuaPushTableKeyValueInt(td->lua_ctx->luastate, "tx_id", (int)(tx_id));

    // int retval = lua_pcall(td->lua_ctx->luastate, 1, 0, 0);
    // if (retval != 0) {
    //     SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    // }

    wasm_tx_log(p, f, tx_id, td->wasm_ctx->instance);

    SCMutexUnlock(&td->wasm_ctx->m);
    SCReturnInt(0);
}

/** \internal
 *  \brief Streaming logger for wasm scripts
 *
 *  Hooks into the Streaming Logger API. Gets called for each chunk of new
 *  streaming data.
 */
static int WasmStreamingLogger(ThreadVars *tv, void *thread_data, const Flow *f,
        const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags)
{
    SCEnter();

    // void *txptr = NULL;
    // LuaStreamingBuffer b = { data, data_len, flags };

    // SCLogDebug("flags %02x", flags);

    // if (flags & OUTPUT_STREAMING_FLAG_TRANSACTION) {
    //     if (f && f->alstate)
    //         txptr = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, tx_id);
    // }

    LogWasmThreadCtx *td = (LogWasmThreadCtx*)thread_data;

    SCMutexLock(&td->wasm_ctx->m);

    // LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    // if (flags & OUTPUT_STREAMING_FLAG_TRANSACTION)
    //     LuaStateSetTX(td->lua_ctx->luastate, txptr);
    // LuaStateSetFlow(td->lua_ctx->luastate, (Flow *)f);
    // LuaStateSetStreamingBuffer(td->lua_ctx->luastate, &b);

    // /* prepare data to pass to script */
    // lua_getglobal(td->lua_ctx->luastate, "log");
    // lua_newtable(td->lua_ctx->luastate);

    // if (flags & OUTPUT_STREAMING_FLAG_TRANSACTION)
    //     LuaPushTableKeyValueInt(td->lua_ctx->luastate, "tx_id", (int)(tx_id));

    // int retval = lua_pcall(td->lua_ctx->luastate, 1, 0, 0);
    // if (retval != 0) {
    //     SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    // }

    int retval = wasm_streaming_log(f, data, data_len, tx_id, td->wasm_ctx->instance);
    if (retval != 0) {
        SCLogInfo("failed to run module");
    }

    SCMutexUnlock(&td->wasm_ctx->m);

    SCReturnInt(TM_ECODE_OK);
}

static void LogWasmSubFree(OutputCtx *oc) {
    if (oc->data) {
        // XXX master_ctx will take care of freeing instance
        // LogWasmCtx *wasm_ctx = oc->data;
        // wasm_ctx_free(wasm_ctx->instance);
        SCFree(oc->data);
        oc->data = NULL;
    }
    SCFree(oc);
}

/** \brief initialize output for a module instance
 *
 *  Runs script 'setup' function.
 */
static OutputInitResult OutputWasmLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    WasmCtx *instance_ctx = NULL;
    OutputInitResult result = { NULL, false };

    if (conf == NULL)
        return result;

    LogWasmCtx *wasm_ctx = SCMalloc(sizeof(LogWasmCtx));
    if (unlikely(wasm_ctx == NULL))
        return result;
    memset(wasm_ctx, 0x00, sizeof(*wasm_ctx));

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        goto error;
    }

    SCMutexInit(&wasm_ctx->m, NULL);

    SCMutexLock(&wasm_ctx->m);
    instance_ctx = wasm_ctx_get_by_name(conf->val, parent_ctx->data);
    SCMutexUnlock(&wasm_ctx->m);

    if (unlikely(instance_ctx == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "couldn't get previously created instance");
        goto error;
    }

    SCMutexLock(&wasm_ctx->m);
    int rc = wasm_logger_instance_init(instance_ctx);
    SCMutexUnlock(&wasm_ctx->m);
    if (rc != 0) {
        SCLogError(SC_ERR_FATAL, "couldn't initialize instance");
        goto error;
    }

    wasm_ctx->instance = instance_ctx;

    output_ctx->data = wasm_ctx;
    output_ctx->DeInit = LogWasmSubFree;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
error:
    SCMutexDestroy(&wasm_ctx->m);
    if (instance_ctx != NULL)
        wasm_ctx_free(instance_ctx);
    SCFree(output_ctx);
    return result;
}

static void LogWasmMasterFree(OutputCtx *oc)
{
    if (oc->data) {
        WasmMasterCtx *ctx = oc->data;
        wasm_master_ctx_free(ctx);
        oc->data = NULL;
    }

    // OutputModule *om, *tom;
    // TAILQ_FOREACH_SAFE(om, &oc->submodules, entries, tom) {
    //     SCFree(om);
    // }
    SCFree(oc);
}

/** \internal
 *  \brief initialize output instance for wasm module
 *
 *  Parses nested script list, primes them to find out what they
 *  inspect, then fills the OutputCtx::submodules list with the
 *  proper Logger function for the data type the script needs.
 */
static OutputInitResult OutputWasmLogInit(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    const char *dir = ConfNodeLookupChildValue(conf, "modules-dir");
    if (dir == NULL)
        dir = "";

    ConfNode *modules = ConfNodeLookupChild(conf, "modules");
    if (modules == NULL) {
        /* No "outputs" section in the configuration. */
        SCLogInfo("modules not defined");
        return result;
    }

    /* global output ctx setup */
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return result;
    }
    output_ctx->DeInit = LogWasmMasterFree;
    output_ctx->data = wasm_master_ctx_new();
    if (unlikely(output_ctx->data == NULL)) {
        SCFree(output_ctx);
        return result;
    }
    WasmMasterCtx *master_ctx = output_ctx->data;
    // strlcpy(master_config->path, dir, sizeof(master_config->path));
    if (wasm_ctx_set_modules_dir(dir, master_ctx) != 0) {
        goto error;
    }
    TAILQ_INIT(&output_ctx->submodules);

    ConfNode *cache_dir = ConfNodeLookupChild(conf, "cache-dir");
    if (cache_dir != NULL) {
        SCLogDebug("WASM: enabling cache");
        wasm_ctx_enable_cache(cache_dir->val, master_ctx);
    }

    /* check the enables scripts and set them up as submodules */
    ConfNode *module;
    TAILQ_FOREACH(module, &modules->head, next) {
        WasmCtx *instance_ctx;
        SCLogDebug("enabling module %s", module->val);

        (void)wasm_ctx_register_module(module->val, master_ctx);
        instance_ctx = wasm_ctx_new_by_name(module->val, master_ctx);
        if (instance_ctx == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "wasm_ctx_new_by_name() failed");
            goto error;
        }

        WasmModuleOpts opts = { 0 };
        if (wasm_module_get_info(instance_ctx, &opts) != 0) {
            SCLogError(SC_ERR_FATAL, "wasm: could not get module options");
            goto error;
        }

        /* create an OutputModule for this script, based
         * on it's needs. */
        OutputModule *om = SCCalloc(1, sizeof(*om));
        if (unlikely(om == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "calloc() failed");
            goto error;
        }

        om->name = MODULE_NAME;
        om->conf_name = module->val;
        om->InitSubFunc = OutputWasmLogInitSub;
        om->ThreadInit = WasmLogThreadInit;
        om->ThreadDeinit = WasmLogThreadDeinit;

        if (opts.alproto == ALPROTO_TLS) {
            om->TxLogFunc = WasmTxLogger;
            om->alproto = ALPROTO_TLS;
            om->tc_log_progress = TLS_HANDSHAKE_DONE;
            om->ts_log_progress = TLS_HANDSHAKE_DONE;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);
        } else if (opts.streaming && opts.tcp_data) {
            om->StreamingLogFunc = WasmStreamingLogger;
            om->stream_type = STREAMING_TCP_DATA;
        // } else if (opts.flow) {
        //     om->FlowLogFunc = LuaFlowLogger;
        // } else if (opts.stats) {
        //     om->StatsLogFunc = LuaStatsLogger;
        } else {
            SCLogError(SC_ERR_LUA_ERROR, "failed to setup WASM thread module (invalid options?)");
            SCFree(om);
            goto error;
        }
#if 0

        if (opts.alproto == ALPROTO_HTTP && opts.streaming) {
            om->StreamingLogFunc = LuaStreamingLogger;
            om->stream_type = STREAMING_HTTP_BODIES;
            om->alproto = ALPROTO_HTTP;
            AppLayerHtpEnableRequestBodyCallback();
            AppLayerHtpEnableResponseBodyCallback();
        } else if (opts.alproto == ALPROTO_HTTP) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_HTTP;
            om->ts_log_progress = -1;
            om->tc_log_progress = -1;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);
        } else if (opts.alproto == ALPROTO_TLS) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_TLS;
            om->tc_log_progress = TLS_HANDSHAKE_DONE;
            om->ts_log_progress = TLS_HANDSHAKE_DONE;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);
       } else if (opts.alproto == ALPROTO_DNS) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_DNS;
            om->ts_log_progress = -1;
            om->tc_log_progress = -1;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);
            AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
        } else if (opts.alproto == ALPROTO_SSH) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_SSH;
            om->TxLogCondition = SSHTxLogCondition;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SSH);
        } else if (opts.alproto == ALPROTO_SMTP) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_SMTP;
            om->ts_log_progress = -1;
            om->tc_log_progress = -1;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMTP);
        } else if (opts.packet && opts.alerts) {
            om->PacketLogFunc = LuaPacketLoggerAlerts;
            om->PacketConditionFunc = LuaPacketConditionAlerts;
        } else if (opts.packet && opts.alerts == 0) {
            om->PacketLogFunc = LuaPacketLogger;
            om->PacketConditionFunc = LuaPacketCondition;
        } else if (opts.file) {
            om->FileLogFunc = LuaFileLogger;
            AppLayerHtpNeedFileInspection();
        } else if (opts.streaming && opts.tcp_data) {
            om->StreamingLogFunc = LuaStreamingLogger;
            om->stream_type = STREAMING_TCP_DATA;
        } else if (opts.flow) {
            om->FlowLogFunc = LuaFlowLogger;
        } else if (opts.stats) {
            om->StatsLogFunc = LuaStatsLogger;
        } else {
            SCLogError(SC_ERR_LUA_ERROR, "failed to setup thread module");
            SCFree(om);
            goto error;
        }

#endif
        TAILQ_INSERT_TAIL(&output_ctx->submodules, om, entries);
    }

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error:
    if (output_ctx->DeInit)
        output_ctx->DeInit(output_ctx);

    int failure_fatal = 0;
    if (ConfGetBool("engine.init-failure-fatal", &failure_fatal) != 1) {
        SCLogDebug("ConfGetBool could not load the value.");
    }
    if (failure_fatal) {
                   FatalError(SC_ERR_FATAL,
                              "Error during setup of wasm output. Details should be "
                              "described in previous error messages. Shutting down...");
    }

    return result;
}

/** \internal
 *  \brief Initialize the thread storage for lua
 *
 *  Currently only stores a pointer to the global LogWasmCtx
 */
static TmEcode WasmLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogWasmThreadCtx *td = SCMalloc(sizeof(*td));
    if (unlikely(td == NULL))
        return TM_ECODE_FAILED;
    memset(td, 0, sizeof(*td));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for WasmLog. \"initdata\" argument NULL");
        SCFree(td);
        return TM_ECODE_FAILED;
    }

    LogWasmCtx *wasm_ctx = ((OutputCtx *)initdata)->data;
    td->wasm_ctx = wasm_ctx;
    *data = (void *)td;
    return TM_ECODE_OK;
}

/** \internal
 *  \brief Deinit the thread storage for lua
 *
 *  Calls OutputWasmLogDoDeinit if no-one else already did.
 */
static TmEcode WasmLogThreadDeinit(ThreadVars *t, void *data)
{
    LogWasmThreadCtx *td = (LogWasmThreadCtx *)data;
    if (td == NULL) {
        return TM_ECODE_OK;
    }

    SCMutexLock(&td->wasm_ctx->m);
    if (td->wasm_ctx->deinit_once == 0) {
    //     OutputWasmLogDoDeinit(td->wasm_ctx);
        td->wasm_ctx->deinit_once = 1;
    }
    SCMutexUnlock(&td->wasm_ctx->m);

    /* clear memory */
    memset(td, 0, sizeof(*td));

    SCFree(td);
    return TM_ECODE_OK;
}

void WasmLogRegister(void) {
    /* register as separate module */
    OutputRegisterModule(MODULE_NAME, "wasm", OutputWasmLogInit);
}

#else

void WasmLogRegister (void) {
    /* no-op */
}

#endif
