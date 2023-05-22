#include "udig-int.h"
#include "scap.h"
#include "ringbuffer/ringbuffer.h"

int32_t scap_udig_get_stats(struct scap_engine_handle engine, struct scap_stats *stats)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	uint32_t j;

	for(j = 0; j < devset->m_ndevs; j++)
	{
		stats->n_evts += devset->m_devs[j].m_bufinfo->n_evts;
		stats->n_drops_buffer += devset->m_devs[j].m_bufinfo->n_drops_buffer;
		stats->n_drops_pf += devset->m_devs[j].m_bufinfo->n_drops_pf;
		stats->n_drops += devset->m_devs[j].m_bufinfo->n_drops_buffer + devset->m_devs[j].m_bufinfo->n_drops_pf;
		stats->n_preemptions += devset->m_devs[j].m_bufinfo->n_preemptions;
	}

	return SCAP_SUCCESS;
}

int32_t scap_udig_get_n_tracepoint_hit(struct scap_engine_handle engine, long *_ret) { return SCAP_SUCCESS; }

uint32_t scap_udig_get_n_devs(struct scap_engine_handle engine) { return engine.m_handle->m_dev_set.m_ndevs; }

uint64_t scap_udig_get_max_buf_used(struct scap_engine_handle engine)
{
	uint64_t i;
	uint64_t max = 0;
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;

	for(i = 0; i < devset->m_ndevs; i++)
	{
		uint64_t size = buf_size_used(&devset->m_devs[i]);
		max = size > max ? size : max;
	}

	return max;
}
