#ifndef LISTENER_HPP_WYKYZCJH
#define LISTENER_HPP_WYKYZCJH

#include "Listener.h"
#include "Session.h"

namespace Ex
{

template<class Stream, class Context>
Listener<Stream, Context>::Listener(
    boost::asio::io_context& ioc,
    Context& ctx,
    boost::asio::ip::tcp::endpoint const endpoint
)
    : ioc_(ioc)
    , ctx_(ctx)
    , acceptor_(boost::asio::make_strand(ioc))
{
    namespace beast = boost::beast;
    namespace net   = boost::asio;

    beast::error_code ec;

    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if (ec)
    {
        on_fail_(ec, "open");
        return;
    }

    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec)
    {
        on_fail_(ec, "set_option");
        return;
    }

    // Bind to the server address
    acceptor_.bind(endpoint, ec);
    if (ec)
    {
        on_fail_(ec, "bind");
        return;
    }

    // Start listening for connections
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec)
    {
        on_fail_(ec, "listen");
        return;
    }
}

template<class Stream, class Context>
auto Listener<Stream, Context>::do_accept() -> void
{
    namespace beast = boost::beast;
    namespace net   = boost::asio;

    // The new connection gets its own strand
    acceptor_.async_accept(
        net::make_strand(ioc_),
        beast::bind_front_handler(
            &Listener<Stream, Context>::on_accept<Stream>,
            shared_from_this()
        )
    );
}

template<class Stream, class Context>
template<typename S>
auto Listener<Stream, Context>::on_accept(
    boost::beast::error_code const ec,
    boost::asio::ip::tcp::socket socket
) -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type
{
    if (ec)
        on_fail_(ec, "accept");
    else
        // Create the session and run it
        std::make_shared<Session<Stream, Context>>(
            std::move(socket),
            ctx_,
            on_fail_,
            on_post_
        )->run();

    // Accept another connection
    do_accept();
}

template<class Stream, class Context>
template<typename S>
auto Listener<Stream, Context>::on_accept(
    boost::beast::error_code const ec,
    boost::asio::ip::tcp::socket socket
) -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type
{
    if (ec)
        on_fail_(ec, "accept");
    else
        // Create the session and run it
        std::make_shared<Session<Stream, Context>>(
            std::move(socket),
            on_fail_,
            on_post_
        )->run();

    // Accept another connection
    do_accept();
}

} // namespace Ex

#endif /* end of include guard: LISTENER_HPP_WYKYZCJH */

// vim: ts=4 sts=0 sw=4 et :
