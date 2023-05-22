struct scap_udig;

#define SCAP_HANDLE_T struct scap_udig

#include "udig-int.h"
#include "engine/noop/noop.h"
#include "scap-int.h"

const struct scap_vtable scap_udig_engine = {
	.name = UDIG_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = scap_udig_alloc,
	.init = scap_udig_open,
	.free_handle = scap_udig_free,
	.close = scap_udig_close,
	.next = scap_udig_next,
	.start_capture = scap_udig_start_capture,
	.stop_capture = scap_udig_stop_capture,
	.configure = scap_udig_configure,
	.get_stats = scap_udig_get_stats,
	.get_stats_v2 = noop_get_stats_v2,
	.get_n_tracepoint_hit = scap_udig_get_n_tracepoint_hit,
	.get_n_devs = scap_udig_get_n_devs,
	.get_max_buf_used = scap_udig_get_max_buf_used,
	.get_threadlist = scap_procfs_get_threadlist,
	.get_vpid = noop_get_vxid,
	.get_vtid = noop_get_vxid,
	.getpid_global = noop_getpid_global,
	.get_api_version = NULL,
	.get_schema_version = NULL,
};