#ifndef LISTENER_H_PW6QNCMF
#define LISTENER_H_PW6QNCMF

#include <memory>

#include <boost/beast/core.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "ex/ex.h"


namespace Ex
{

/** Accepts incoming connections and launches Session */
template <class Stream, class Context>
class Listener : public std::enable_shared_from_this<Listener<Stream, Context>>
{
    boost::asio::io_context& ioc_;
    Context& ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;

   public:
    Listener(
        boost::asio::io_context& ioc,
        Context& ctx,
        boost::asio::ip::tcp::endpoint const endpoint,
        int timeout_seconds
    );

    auto run() -> void { do_accept(); }

    /** Setter for fail handler.  Forwarded to session */
    auto on_fail(Types::type_on_fail const l) -> void { on_fail_ = l; };

    /** Setter for fail handler.  Forwarded to session */
    auto on_post(Types::type_on_post const l) -> void { on_post_ = l; };

   private:

    /** Failure action */
    Types::type_on_fail on_fail_ = [](boost::beast::error_code, char const *) { return; };

    /** Post action */
    Types::type_on_post on_post_ = [](unsigned const, boost::string_view, std::string const&)
    {
        return std::make_pair(true, boost::beast::http::response<boost::beast::http::empty_body>());
    };

    auto do_accept() -> void;

    // SSL
    template<typename S = Stream>
    auto on_accept(
        boost::beast::error_code const ec,
        boost::asio::ip::tcp::socket socket
    ) -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type;

    // Plain-text
    template<typename S = Stream>
    auto on_accept(
        boost::beast::error_code const ec,
        boost::asio::ip::tcp::socket socket
    ) -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type;

    /** Timeout value used on requests */
    int request_timeout_seconds_ = 30;
};

} // namespace Ex

#endif /* end of include guard: LISTENER_H_PW6QNCMF */

#ifndef LISTENER_HPP_WYKYZCJH
#include "Listener.hpp"
#endif

// vim: ts=4 sts=0 sw=4 et :