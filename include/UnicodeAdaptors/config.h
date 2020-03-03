#ifndef UNICODE_MACROS
#define UNICODE_MACROS

/**
 * Define various macros to make the projects compatible with or without
 * unicode.  This is written to be included by all the uncicode-compatible
 * ALIDB projets.  Because this is done with mostly macros, this breaks
 * encapsulation, but it's not clear what a good alternative would be (the
 * using's are fine, it's the defines that mess everything up)
 *
 * Arguably, converting WSTR or even UCOUT/UCERR to functions/objects with
 * streaming operators would result in many copies when building with unicode.
 *
 * So, until a better solution is found, this header will be included in the
 * ALIDB projects.  If C++ libs are moved into their own library, than this
 * should also be a library that those depend on.  Either that or a similar
 * header is in each product, but where either the macros are given very
 * distinct names.
 */

#include <codecvt>
#include <string>
#include <sstream>

namespace uc {

#ifdef UNICODE

    using Char = wchar_t;

    #ifndef WSTR
        #define WSTR(s) L##s
    #endif

    #ifndef UCOUT
        #define UCOUT std::wcout
    #endif

    #ifndef UCERR
        #define UCERR std::wcerr
    #endif

    #ifndef USTRING
        #define USTRING(s) std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(s)
    #endif

    #ifndef TO_STRING
        #define TO_STRING(s) std::to_wstring(s)
    #endif

    #ifndef STRFTIME
        #define STRFTIME std::wcsftime
    #endif

    #ifndef IF_WIDE_OLE2A
        #define IF_WIDE_OLE2A(s) OLE2A(s)
    #endif

    // Note: Windows Server 2012 R2+ (6.3+)
    #ifndef GetHostName
        #define GetHostName GetHostNameW
    #endif

    #ifndef GetNameInfo
        #define GetNameInfo GetNameInfoW
    #endif

    #ifndef GetAddrInfo
        #define GetAddrInfo GetAddrInfoW
    #endif

    // Windows Server 2008+ (6.0+)
    #ifndef InetNtop
        #define InetNtop InetNtopW
    #endif

    // Windows Server 2008+ (6.0+)
    #ifndef InetPton
        #define InetPton InetPtonW
    #endif

#else

    using Char = char;

    #ifndef WSTR
        #define WSTR(s) s
    #endif

    #ifndef UCOUT
        #define UCOUT std::cout
    #endif

    #ifndef UCERR
        #define UCERR std::cerr
    #endif

    #ifndef USTRING
        #define USTRING(s) s
    #endif

    #ifndef TO_STRING
        #define TO_STRING(s) std::to_string(#s)
    #endif

    #ifndef STRFTIME
        #define STRFTIME std::strftime
    #endif

    #ifndef IF_WIDE_OLE2A
        #define IF_WIDE_OLE2A(s) s
    #endif

    #ifndef GetHostName
        #define GetHostName gethostname
    #endif

    #ifndef GetNameInfo
        #define GetNameInfo getnameinfo
    #endif

    #ifndef GetAddrInfo
        #define GetAddrInfo GetAddrInfo
    #endif

    #ifndef InetNtop
        #define InetNtop InetNtopA
    #endif

    #ifndef InetPton
        #define InetPton InetPtonA
    #endif

#endif

    using string       = std::basic_string<Char>;
    using stringstream = std::basic_stringstream<Char>;
    using fstream      = std::basic_fstream<Char>;

}

#endif /* end of include guard: UNICODE_MACROS */
