#include "pch.h"

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
        std::wcerr <<
            L"Usage: http-server-async-ssl <address> <port> <threads>\n" <<
            L"Example:\n" <<
            L"    http-server-async-ssl 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port    = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const threads = std::max<int>(1, std::atoi(argv[4]));


    // Set up a failure handler used for both http and https listeners
    auto on_fail = [](beast::error_code const ec, char const* what)
    {
        if (net::ssl::error::stream_truncated == ec)
            return;

        std::wcout << what << ": " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(ec.message()) << "\n";
    };

    // Set up a post handler used for both http and https listeners
    auto on_post = [](unsigned const version, std::string const& body
    )
    {
        namespace http = boost::beast::http;

        auto status = http::status::ok;
        http::response<http::empty_body> res{ status, version };
        return std::make_pair(true, res);
    };

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12};

    // This holds the self-signed certificate used by the server
    Ex::load_server_certificate(ctx);

    // Create and launch a listening port
    auto listener = std::make_shared<ListenerHttps>(
        ioc,
        ctx,
        tcp::endpoint{address,  port}
    );

    listener->on_fail(on_fail);

    // Set up post event
    listener->on_post([&on_post](
        unsigned const version,
        boost::string_view req_ip,
        std::string const& body
    )
    {
        std::wcout << L"Received " << body.length() << L" characters from " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(req_ip.to_string()) << L" on https post";
        return on_post(version, body);
    });

    listener->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back(
        [&ioc]
        {
            ioc.run();
        });
    ioc.run();

    return EXIT_SUCCESS;
}
