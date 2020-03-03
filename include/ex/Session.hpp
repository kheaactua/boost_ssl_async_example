#ifndef SESSION_HPP_B9PGLJ7H
#define SESSION_HPP_B9PGLJ7H

#include "ex/Session.h"

#include <memory>

#include <boost/asio/dispatch.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>


namespace Ex
{

template<class Stream, class Context>
Session<Stream, Context>::send_lambda::send_lambda(Session<Stream, Context>& self)
    : self_(self)
{ }

template<class Stream, class Context>
template<typename S>
Session<Stream, Context>::Session(
    boost::asio::ip::tcp::socket&& socket,
    typename std::enable_if<!details::has_member_function_cancel<S, void>::value, Context&>::type ctx,
    Types::type_on_fail const on_fail,
    Types::type_on_post const on_post,
    int const request_timeout_seconds
)
    : stream_(std::move(socket), ctx)
    , lambda_(*this)
    , on_fail_(on_fail)
    , on_post_(on_post)
    , request_timeout_seconds_(request_timeout_seconds)
{ }

template<class Stream, class Context>
template<typename S>
Session<Stream, Context>::Session(
    boost::asio::ip::tcp::socket&& socket,
    Types::type_on_fail const on_fail,
    Types::type_on_post const on_post,
    int const request_timeout_seconds
)
    : stream_(std::move(socket))
    , lambda_(*this)
    , on_fail_(on_fail)
    , on_post_(on_post)
    , request_timeout_seconds_(request_timeout_seconds)
{ }

template<class Stream, class Context>
template<class Body, class Allocator, class Send>
auto Session<Stream, Context>::validate_request(
    boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>&& req,
    Send&& send
) -> bool
{
    namespace beast = boost::beast;
    namespace http  = beast::http;
    namespace net   = boost::asio;

    // Returns a bad method response
    auto const bad_method = [&req](beast::string_view const why)
    {
        http::response<http::string_body> res{ http::status::method_not_allowed, req.version() };
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };

    // Make sure we can handle the method
    if (req.method() != http::verb::post)
    {
        send(bad_method("Unknown HTTP-method.  Only POST is supported"));
        return false;
    }

    return true;
}

template<class Stream, class Context>
template<class Body, class Allocator, class Send, typename RequestHandler>
auto Session<Stream, Context>::handle_request(
    boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>&& req,
    boost::string_view req_ip,
    Send&& send,
    RequestHandler post_handler
) -> bool
{
    namespace http = boost::beast::http;

    auto res_pair = post_handler(req.version(), req_ip, req.body());
    if (res_pair.first)
    {
        res_pair.second.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res_pair.second.keep_alive(req.keep_alive());
        res_pair.second.prepare_payload();

        send(std::move(res_pair.second));
        return true;
    }
    else
    {
        // We don't actually want to respond
        return false;
    }
}

template<class Stream, class Context>
template<typename S>
auto Session<Stream, Context>::run() -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type
{
    namespace beast = boost::beast;
    namespace net   = boost::asio;

    // We need to be executing within a strand to perform async operations
    // on the I/O objects in this session. Although not strictly necessary
    // for single-threaded contexts, this example code is written to be
    // thread-safe by default.
    net::dispatch(
        stream_.get_executor(),
        beast::bind_front_handler(
            &Session<Stream, Context>::on_run<Stream>,
            this->shared_from_this()
        )
    );
}

template<class Stream, class Context>
template<typename S>
auto Session<Stream, Context>::run() -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type
{
    namespace beast = boost::beast;
    namespace net   = boost::asio;

    // We need to be executing within a strand to perform async operations
    // on the I/O objects in this session. Although not strictly necessary
    // for single-threaded contexts, this example code is written to be
    // thread-safe by default.
    net::dispatch(stream_.get_executor(),
        beast::bind_front_handler(
            &Session<Stream, Context>::do_read,
            this->shared_from_this()
        )
    );
}

template <class Stream, class Context>
template <typename S>
auto Session<Stream, Context>::on_run() -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type
{
    namespace beast = boost::beast;
    namespace ssl   = boost::asio::ssl;

    // Set the timeout.
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(request_timeout_seconds_));

    // Perform the SSL handshake
    stream_.async_handshake(
        ssl::stream_base::server,
        beast::bind_front_handler(
            &Session::on_handshake,
            this->shared_from_this()
        )
    );
}

template <class Stream, class Context>
template <typename S>
auto Session<Stream, Context>::on_run() -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type
{
}

template <class Stream, class Context>
auto Session<Stream, Context>::on_handshake(boost::beast::error_code const ec) -> void
{
    if (ec) return on_fail_(ec, "handshake");

    do_read();
}

template <class Stream, class Context>
auto Session<Stream, Context>::do_read() -> void
{
    namespace beast = boost::beast;
    namespace http  = beast::http;

    // Make the request empty before reading,
    // otherwise the operation behavior is undefined.
    req_ = {};

    // Set the timeout.
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(request_timeout_seconds_));

    // Read a request
    http::async_read(stream_, buffer_, req_,
        beast::bind_front_handler(
            &Session::on_read,
            this->shared_from_this()
        )
    );
}

template <class Stream, class Context>
auto Session<Stream, Context>::on_read(
    boost::beast::error_code const ec,
    std::size_t const bytes_transferred
) -> void
{
    boost::ignore_unused(bytes_transferred);

    namespace beast = boost::beast;
    namespace http  = beast::http;

    // This means they closed the connection
    if (http::error::end_of_stream == ec)
        return do_close();

    if (ec) return on_fail_(ec, "read");

    // Send the response
    if (validate_request(std::move(req_), lambda_))
    {
        if (!handle_request(std::move(req_), beast::get_lowest_layer(stream_).socket().remote_endpoint().address().to_string(), lambda_, on_post_))
        {
            return on_fail_(ec, "Behaviour imposed failure");
        }
    }
    else
        return on_fail_(ec, "validate");
}

template <class Stream, class Context>
auto Session<Stream, Context>::on_write(
    bool const close,
    boost::beast::error_code const ec,
    std::size_t const bytes_transferred
) -> void
{
    boost::ignore_unused(bytes_transferred);

    if (ec) return on_fail_(ec, "write");

    if (close)
    {
        // This means we should close the connection, usually because
        // the response indicated the "Connection: close" semantic.
        return do_close();
    }

    // We're done with the response so delete it
    res_ = nullptr;

    // Read another request
    do_read();
}

template <class Stream, class Context>
template <typename S>
auto Session<Stream, Context>::do_close() -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type
{
    namespace beast = boost::beast;

    // Set the timeout.
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(request_timeout_seconds_));

    // Perform the SSL shutdown
    stream_.async_shutdown(
        beast::bind_front_handler(
            &Session::on_shutdown,
            this->shared_from_this()
        )
    );
}

template <class Stream, class Context>
template <typename S>
auto Session<Stream, Context>::do_close() -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type
{
   namespace beast = boost::beast;
   using tcp = boost::asio::ip::tcp;

   // Send a TCP shutdown
   beast::error_code ec;
   stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
}

template <class Stream, class Context>
auto Session<Stream, Context>::on_shutdown(boost::beast::error_code const ec) const -> void
{
    if (ec) return on_fail_(ec, "shutdown");

    // At this point the connection is closed gracefully
}

} // namespace Ex

#endif /* end of include guard: SESSION_HPP_B9PGLJ7H */

// vim: ts=4 sts=0 sw=4 et :
