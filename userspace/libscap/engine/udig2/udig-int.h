#ifndef UDIG_INT_H
#define UDIG_INT_H

#define SCAP_HANDLE_T struct scap_udig

#include <pthread.h>
#include <stdint.h>

#include "scap_vtable.h"

#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#endif

#include "ringbuffer/devset.h"
#include "udig-open.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define RW_SNAPLEN 80

	struct scap_udig
	{
		struct scap_device_set m_dev_set;
		char *m_lasterr;

		int m_listen_fd;
		pthread_t m_thread;
		struct udig_consumer_t settings;
		volatile bool m_udig_capturing;
	};

	struct scap_udig *scap_udig_alloc(scap_t *main_handle, char *lasterr_ptr);

	void scap_udig_init(struct scap_udig *handle);

	void scap_udig_free(struct scap_engine_handle engine);

	int32_t scap_udig_open(scap_t *main_handle, struct scap_open_args *oargs);

	int32_t scap_udig_close(struct scap_engine_handle engine);

	int32_t scap_udig_next(struct scap_engine_handle engine, scap_evt **pevent, uint16_t *pcpuid);

	int32_t scap_udig_start_capture(struct scap_engine_handle engine);

	int32_t scap_udig_stop_capture(struct scap_engine_handle engine);

	int32_t scap_udig_configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1,
				    unsigned long arg2);

	int32_t scap_udig_get_stats(struct scap_engine_handle engine, struct scap_stats *stats);

	int32_t scap_udig_get_n_tracepoint_hit(struct scap_engine_handle engine, long *ret);

	uint32_t scap_udig_get_n_devs(struct scap_engine_handle engine);

	uint64_t scap_udig_get_max_buf_used(struct scap_engine_handle engine);

	void udig_begin_capture_dev(struct scap_device *dev, struct udig_consumer_t *settings, char *error);

#ifdef __cplusplus
};
#endif

#endif // UDIG_INT_H
