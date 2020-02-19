#include "pch.h"

// Prevent Windows.h from defining a 'max' macro
#define NOMINMAX

// Fix no_init_all error
#if (_MSC_VER >= 1915)
#define no_init_all deprecated
#endif

#include <codecvt>
#include <sstream>
#include <string>

namespace uc {

#ifdef UNICODE
    using Char = wchar_t;
    #define WSTR(s) L##s
    #define UCOUT std::wcout
    #define UCERR std::wcerr
    #define USTRING(s) std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(s)
#else
    using Char = char;
    #define WSTR(s) s
    #define UCOUT std::cout
    #define UCERR std::cerr
    #define USTRING(s) s
#endif

    using string = std::basic_string<Char>;
    using stringstream = std::basic_stringstream<Char>;

}

#include "ex/Listener.hpp"
#include "ex/certificate_helpers.h"
#include "ex/Thumbprint.h"


auto main(int argc, char* argv[]) -> int
{
    using ListenerHttps = Ex::Listener<Ex::Types::ssl_stream, Ex::Types::ssl_context>;

    namespace beast = boost::beast;
    namespace net   = boost::asio;
    namespace ssl   = boost::asio::ssl;
    using tcp       = boost::asio::ip::tcp;

    // Check command line arguments.
    if (argc != 4)
    {
        UCERR <<
            "Usage: http-server-async-ssl <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    http-server-async-ssl 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port    = static_cast<unsigned short>(std::stoi(argv[2]));
    auto const threads = std::max<int>(1, std::stoi(argv[3]));

    // Set up a failure handler used for both http and https listeners
    auto on_fail = [](beast::error_code const ec, char const* what)
    {
        if (net::ssl::error::stream_truncated == ec)
            return;

        UCERR << what << ": " << USTRING(ec.message()) << "\n";
    };

    // Set up a post handler used for both http and https listeners
    auto on_post = [](unsigned const version, std::string const& body)
    {
        namespace http = boost::beast::http;

        http::response<http::empty_body> res{ http::status::ok , version };
        return std::make_pair(true, res);
    };

    // The io_context is required for all I/O
    net::io_context ioc{ threads };

    // The SSL context is required, and holds certificates
    ssl::context ctx{ ssl::context::tlsv12 };

    namespace eh = EsoType5HttpServer;
    eh::Thumbprint search_thumbprint{ "ffe1e9a5f5b558f7f84808647680fdc77844e591" };
    eh::CertificateHelper ch{ ctx };
    if (!ch.load_server_certificate(/* WSTR("MY"), &search_thumbprint */))
    {
        UCERR << "Could not load certificate\n";
        return EXIT_FAILURE;
    }

    // Create and launch a listening port
    auto listener = std::make_shared<ListenerHttps>(
        ioc,
        ctx,
        tcp::endpoint{address, port},
        30 /* timeout */
    );

    listener->on_fail(on_fail);

    // Set up post event
    listener->on_post([&on_post](
        unsigned const version,
        boost::string_view req_ip,
        std::string const& body
    )
    {
        UCOUT << "Received " << body.length() << " characters from " << USTRING(req_ip.to_string()) << " on https post\n";
        return on_post(version, body);
    });

    UCOUT << "Starting listener" << std::endl;
    listener->run();

    // Run the I/O service on the requested number of threads
    UCOUT << "Launching " << threads << " listener threads\n";
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back(
        [&ioc]
        {
            ioc.run();
        });
    ioc.run();

    UCOUT << "done\n";

    return EXIT_SUCCESS;
}
