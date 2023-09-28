#pragma once

enum falco_log_severity
{
	FALCO_LOG_SEV_FATAL = 1,
	FALCO_LOG_SEV_CRITICAL = 2,
	FALCO_LOG_SEV_ERROR = 3,
	FALCO_LOG_SEV_WARNING = 4,
	FALCO_LOG_SEV_NOTICE = 5,
	FALCO_LOG_SEV_INFO = 6,
	FALCO_LOG_SEV_DEBUG = 7,
	FALCO_LOG_SEV_TRACE = 8,
};

typedef void (*falco_log_fn)(const char* component, const enum falco_log_severity sev, const char* msg);
