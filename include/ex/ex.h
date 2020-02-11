#ifndef EX_H_4EGP5Y08
#define EX_H_4EGP5Y08

#include <functional>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/utility/string_view.hpp>
#include <boost/tti/has_member_function.hpp>

namespace Ex
{

namespace details
{
BOOST_TTI_HAS_MEMBER_FUNCTION(cancel)
}


/** Context type used for non-ssl connections */
class plain_text_context {};

/** Structure to define types used throughout the simulator */
struct Types
{
    using ssl_stream  = boost::beast::ssl_stream<boost::beast::tcp_stream>;
    using text_stream = boost::beast::tcp_stream;
    using ssl_context = boost::asio::ssl::context;
    using plain_text_context = plain_text_context;

    /** Type used to define an action for failed events */
    using type_on_fail = std::function<void(boost::beast::error_code const, char const*)>;

    /** Type used to define an action for post events.  The return type is a pair
     * (bool and response), the bool represents whether the http connection should
     * be maintained (true) or closed (false) with no response sent */
    using type_on_post = std::function<std::pair<bool, boost::beast::http::response<boost::beast::http::empty_body>>(
        unsigned const,     /* Version      */
        boost::string_view, /* Requested IP */
        std::string const&  /* request body */
    )>;
};

} // namespace Ex

#endif /* end of include guard: EX_H_4EGP5Y08 */

// vim: ts=4 sts=0 sw=4 et :
