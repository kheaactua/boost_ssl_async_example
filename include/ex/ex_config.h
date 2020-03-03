#ifndef PCH_H_LTCUGZ59
#define PCH_H_LTCUGZ59

// Prevent Windows.h from defining a 'max' macro
#define NOMINMAX

// Fix no_init_all error
#if (_MSC_VER >= 1915)
#define no_init_all deprecated
#endif

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>

#include <openssl/x509.h>

#include <algorithm>
#include <codecvt>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>
#include <cstdio>
#include <tchar.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <cryptuiapi.h>

/** Timeout used for the https server type 5 requests (seconds) */
constexpr auto REQUEST_TIMEOUT = 30;

#if COMPILING_DLL
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __declspec(dllimport)
#endif

#include "UnicodeAdaptors/config.h"

#endif /* end of include guard: PCH_H_LTCUGZ59 */
