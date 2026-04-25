#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "winhttp_forward_exports.hpp"

#ifndef WINHTTP_REDIRECT_PROXY_LOG_FILE_NAME
#define WINHTTP_REDIRECT_PROXY_LOG_FILE_NAME L"upd_runtime_log.txt"
#endif

#ifndef WINHTTP_REDIRECT_PROXY_LOG_PREFIX
#define WINHTTP_REDIRECT_PROXY_LOG_PREFIX "[UPD] "
#endif

#include "winhttp_redirect_runtime.hpp"
