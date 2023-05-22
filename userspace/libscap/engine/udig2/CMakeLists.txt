add_library(
		scap_engine_udig
		udig-alloc.c
		udig-consumer-open.c
		udig-next.c
		udig-open.c
		udig-settings.c
		udig-stats.c
		udig-vtable.c
)

set_property(TARGET scap_engine_udig PROPERTY C_STANDARD 99)
target_link_libraries(scap_engine_udig pthread rt)