#ifndef SESSION_H_ZG6JSI3E
#define SESSION_H_ZG6JSI3E

#include <type_traits>
#include <memory>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/utility/string_view.hpp>


namespace Ex
{

/** Handles an HTTP server connection */
template <class Stream, class Context>
class Session : public std::enable_shared_from_this<Session<Stream, Context>>
{
    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        Session& self_;

        explicit send_lambda(Session& self);

        template<bool isRequest, class Body, class Fields>
        auto operator()(boost::beast::http::message<isRequest, Body, Fields>&& msg) const -> void
        {
            namespace beast = boost::beast;
            namespace http  = beast::http;

            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            self_.res_ = sp;

            // Write the response
            http::async_write(
                self_.stream_,
                *sp,
                beast::bind_front_handler(
                    &Session::on_write,
                    self_.shared_from_this(),
                    sp->need_eof()
                )
            );
        }
    };

    Stream stream_;
    boost::beast::flat_buffer buffer_;
    boost::beast::http::request<boost::beast::http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;

    /** Fail action */
    Types::type_on_fail on_fail_;

    /** Post action */
    Types::type_on_post on_post_;

   public:
    // Take ownership of the stream
    template<typename S = Stream>
    explicit Session(
        boost::asio::ip::tcp::socket&& socket,
        typename std::enable_if<!details::has_member_function_cancel<S, void>::value, Context&>::type ctx,
        Types::type_on_fail const on_fail,
        Types::type_on_post const on_post,
        int const request_timeout_seconds
    );

    template<typename S = Stream>
    explicit Session(
        boost::asio::ip::tcp::socket&& socket,
        Types::type_on_fail const on_fail,
        Types::type_on_post const on_post,
        int const request_timeout_seconds
    );

    /** Start accepting incoming SSL connections */
    template<typename S = Stream>
    auto run() -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type;

    /** Start accepting incoming non-SSL connections */
    template<typename S = Stream>
    auto run() -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type;

    // SSL
    template<typename S = Stream>
    auto on_run() -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type;

    // non-SSL
    template<typename S = Stream>
    auto on_run() -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type;

    auto on_handshake(boost::beast::error_code const ec) -> void;

    auto do_read() -> void;

    auto on_read(
        boost::beast::error_code const ec,
        std::size_t const bytes_transferred
    ) -> void;

    auto on_write(
        bool const close,
        boost::beast::error_code const ec,
        std::size_t const bytes_transferred
    ) -> void;

    // SSL
    template<typename S = Stream>
    auto do_close() -> typename std::enable_if<!details::has_member_function_cancel<S, void>::value, void>::type;

    // non-SSL
    template<typename S = Stream>
    auto do_close() -> typename std::enable_if<details::has_member_function_cancel<S, void>::value, void>::type;

    auto on_shutdown(boost::beast::error_code const ec) const -> void;

   private:

    /**
     * Verify that the HTTP request is proper, otherwise produce an appropriate
     * HTTP response showing the error.
     * The type of the response object depends on the contents of the request,
     * so the interface requires the caller to pass a generic lambda for
     * receiving the response. */
    template<class Body, class Allocator, class Send>
    auto validate_request(
        boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>&& req,
        Send&& send
    ) -> bool;

    /**
     * Assuming a valid response, generate a response
     * The type of the response object depends on the contents of the request,
     * so the interface requires the caller to pass a generic lambda for
     * receiving the
     * response. */
    template<class Body, class Allocator, class Send, typename RequestHandler>
    auto handle_request(
        boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>&& req,
        boost::string_view req_ip,
        Send&& send,
        RequestHandler post_handler
    ) -> bool;

    /** Timeout value used on requests */
    int request_timeout_seconds_ = 30;
};

} // namespace EsoType5HttpServer

#endif /* end of include guard: SESSION_H_ZG6JSI3E */

#ifndef SESSION_HPP_B9PGLJ7H
#include "Session.hpp"
#endif

// vim: ts=4 sts=0 sw=4 expandtab :
