#ifndef CERTIFICATE_HELPERS_H_GY7VEMA0
#define CERTIFICATE_HELPERS_H_GY7VEMA0


#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

#include "Thumbprint.h"

namespace Ex
{

// TODO return enum
auto DLLEXPORT get_property(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId,
    std::function<void(void*, DWORD)> setter
) -> int;

auto DLLEXPORT get_thumbprint(
    PCCERT_CONTEXT pCertContext,
    Ex::Thumbprint& thumbprint
) -> int;

auto DLLEXPORT get_display_name(
    PCCERT_CONTEXT pCertContext,
    std::wstring& display_name
) -> int;

auto DLLEXPORT load_certificate_from_thumbprint(
    Ex::Thumbprint const * const search_thumbprint,
    boost::asio::ssl::context& ctx,
    boost::system::error_code& ec,
    std::function<void(std::wstring const&)> out,
    std::function<void(std::wstring const&)> err
) -> bool;

auto DLLEXPORT load_server_certificate(boost::asio::ssl::context& ctx) -> void;

auto DLLEXPORT load_static_server_certificate(boost::asio::ssl::context& ctx) -> void;

} // namespace Ex

#endif /* end of include guard: CERTIFICATE_HELPERS_H_GY7VEMA0 */
