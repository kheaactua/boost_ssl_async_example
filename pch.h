#ifndef PCH_H_OQ6N54XI
#define PCH_H_OQ6N54XI

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
#include <boost/asio/ip/tcp.hpp>
#include <boost/config.hpp>

#include <string>
#include <algorithm>
#include <codecvt>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>
#include <cstdio>
#include <conio.h>
#include <tchar.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <cryptuiapi.h>

#include "ex/Listener.hpp"
#include "ex/CertificateHelper.h"

#endif /* end of include guard: PCH_H_OQ6N54XI */

//  vim: set ts=4 sw=4 tw=0 et ff=dos :
