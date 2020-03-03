#ifndef CERTIFICATE_HELPERS_H_GY7VEMA0
#define CERTIFICATE_HELPERS_H_GY7VEMA0

#include "ex/ex_config.h"

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

#include "Ex/Thumbprint.h"

namespace Ex
{

/** Class containing methods to help with loading the certificates.  The main
 * reason for making this a class was to add logging/output hooks */
DLLEXPORT class CertificateHelper
{
   public:
    enum class CertError
    {
        Success = 0,
        AllocationError = -1,
        DataNotFoundError = -2,
        PropertyNotFound = -3,
    };

    CertificateHelper(
        boost::asio::ssl::context& ctx,
        std::function<void(uc::string const&)> out,
        std::function<void(uc::string const&)> err
    );

    explicit CertificateHelper(
        boost::asio::ssl::context& ctx
    );

    /** Search the certificate store for a specified certificate
     * and attempt to load it */
    auto load_server_certificate(
        uc::string const& store_name,
        Thumbprint const * const search_thumbprint
    ) -> bool;

    // TODO remove this overload when certificates work
    /** Load a hard coded boost certificate */
    auto load_server_certificate() -> bool;

    /** Request client certificate and specify the verification callback */
    auto require_client_verification(
        boost::asio::ssl::context& ctx,
        unsigned char const * const session_id_context,
        unsigned int const session_id_context_len,
        std::function<bool(bool const, boost::asio::ssl::verify_context&)> callback
    ) -> void;

   protected:

    /** Info log */
    std::function<void(uc::string const&)> log_ = [](auto const& mes) { UCOUT << mes << "\n"; };

    /** Error log */
    std::function<void(uc::string const&)> error_ = [](auto const& mes) { UCERR << WSTR("Error: ") << mes << "\n"; };

    /** SSL Context */
    boost::asio::ssl::context& ctx_;

    auto log(uc::string const& mes)         -> void;
    auto log(uc::stringstream const& mes)   -> void;
    auto error(uc::stringstream const& mes) -> void;

    /** Search the certificate store for a specified certificate
     * and attempt to load it */
    auto load_certificate_from_thumbprint(
        uc::string const& store_name,
        Thumbprint const * const search_thumbprint,
        boost::system::error_code& ec
    ) -> bool;

    /** Fetch a property from a certificate, and pass it to setter() */
    auto get_property(
        PCCERT_CONTEXT pCertContext,
        DWORD dwPropId,
        std::function<void(void*, DWORD)> setter
    ) -> CertError;

    /** Copy the certificate thumbprint into a Thumbprint object */
    auto get_thumbprint(
        PCCERT_CONTEXT pCertContext,
        Thumbprint& thumbprint
    ) -> CertError;

    /** Copy the certificate display name into a string */
    auto get_display_name(
        PCCERT_CONTEXT pCertContext,
        uc::string& display_name
    ) -> CertError;
};

/** Handler function for client verification.
 * This specific handler ignores the speicifc certificate, it's used just to
 * ensure there is a certificate */
auto ignore_client_certificate(
    bool const preverified,
    boost::asio::ssl::verify_context& vctx,
    std::function<void(uc::string const&)> log
) -> bool;

} // namespace EsoType5HttpServer

#endif /* end of include guard: CERTIFICATE_HELPERS_H_GY7VEMA0 */
