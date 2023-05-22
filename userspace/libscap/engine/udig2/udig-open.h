#ifndef UDIG_OPEN_H
#define UDIG_OPEN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#include "../../../common/types.h"
#include "ppm_ringbuffer.h"
#include "ringbuffer/devset.h"

#define UDIG_SOCKET "/dev/shm/udig.sock"
#define UDIG_RING_SIZE (1024 * 1024)

struct udig_consumer_t
{
	uint32_t seq;
	uint32_t snaplen;
	uint32_t sampling_ratio;
	bool do_dynamic_snaplen;
	uint32_t sampling_interval;
	int is_dropping;
	int dropping_mode;
	volatile int need_to_insert_drop_e;
	volatile int need_to_insert_drop_x;
	uint16_t fullcapture_port_range_start;
	uint16_t fullcapture_port_range_end;
	uint16_t statsd_port;
};

enum ring_state
{
	RING_CAPTURING = 0,
	RING_STARTING = 1,
	RING_STOPPED = 2,
};

struct udig_ring_buffer_status
{
	volatile uint64_t m_writer_tid;
	volatile uint32_t m_buffer_size;
	volatile enum ring_state m_state;
	struct udig_consumer_t m_consumer;
	// this shouldn't really be mapped into the producer
	// but we want to quickly notify the consumer we're
	// exiting cleanly if possible
	volatile struct timespec m_last_event_time;
};

struct scap_ringbuffer_info
{
	struct ppm_ring_buffer_info m_bufinfo;
	struct udig_ring_buffer_status m_ring_buffer_status;
};

int32_t udig_map_ring(struct scap_device *dev, uint32_t ring_size, char *error, int ring_access_flags);

struct scap_stats;

void scap_udig_close_dev(struct scap_device *dev, struct scap_stats *stats);

#endif // UDIG_OPEN_H
