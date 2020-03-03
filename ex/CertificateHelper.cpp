#include "ex/ex_config.h"

#include "ex/CertificateHelper.h"

#include "ex/Thumbprint.h"

namespace Ex
{

namespace ssl = boost::asio::ssl;

CertificateHelper::CertificateHelper(
    ssl::context& ctx,
    std::function<void(uc::string const&)> log,
    std::function<void(uc::string const&)> err
)
    : ctx_(ctx)
    , log_(log)
    , error_(err)
{}

CertificateHelper::CertificateHelper(
    ssl::context& ctx
)
    : ctx_(ctx)
{}

auto CertificateHelper::get_property(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId,
    std::function<void(void*, DWORD)> setter
) -> CertError
{
    void* pvData = nullptr;
    DWORD cbData = 0;

    if (CertGetCertificateContextProperty(
        pCertContext,
        dwPropId,
        nullptr,
        &cbData)
    )
    {
        if (!(pvData = ::operator new(cbData)))
        {
            return CertError::AllocationError;
        }

        if (CertGetCertificateContextProperty(
            pCertContext,
            dwPropId,
            pvData,
            &cbData)
        )
        {
            setter(pvData, cbData);
        }
        else
        {
            return CertError::DataNotFoundError;
        }
    }
    else
    {
        return CertError::PropertyNotFound;
    }

    return CertError::Success;
}

auto CertificateHelper::get_thumbprint(
    PCCERT_CONTEXT pCertContext,
    Thumbprint& thumbprint
) -> CertError
{
    return get_property(
        pCertContext,
        CERT_SHA1_HASH_PROP_ID,
        [&thumbprint](void* pvData, DWORD cbData)
        {
            Thumbprint const t(reinterpret_cast<Thumbprint::value_type*>(pvData), cbData);
            thumbprint = t;
        }
    );
}

auto CertificateHelper::get_display_name(
    PCCERT_CONTEXT pCertContext,
    uc::string& display_name
) -> CertError
{
    return get_property(
        pCertContext,
        CERT_FRIENDLY_NAME_PROP_ID,
        [&display_name](void* pvData, DWORD cbData)
        {
            uc::stringstream ss;
            ss << static_cast<uc::Char*>(pvData);
            ss >> display_name;
        }
    );
}

auto CertificateHelper::load_certificate_from_thumbprint(
    uc::string const& store_name,
    Thumbprint const * const search_thumbprint,
    boost::system::error_code& ec//,
) -> bool
{
    HCERTSTORE     hCertStore;
    PCCERT_CONTEXT pCertContext = nullptr;
    DWORD          dwPropId = 0;

    //-------------------------------------------------------------------
    // Open a system certificate store.

    if (hCertStore = CertOpenSystemStore(NULL, store_name.c_str()))
    {
        uc::stringstream ss;
        ss << "The \"" << store_name << "\" store has been opened, looking for certificate with thumbprint \"" << *search_thumbprint << "\"";
        log(ss);
    }
    else
    {
        // If the store was not opened, exit to an error routine.
        uc::stringstream ss;
        ss << "The " << store_name << " store could not be opened";
        error(ss);

        return false;
    }

    //-------------------------------------------------------------------
    // Use CertEnumCertificatesInStore to get the certificates
    // from the open store. pCertContext must be reset to
    // NULL to retrieve the first certificate in the store.

    auto hash_blob = std::make_unique<CRYPT_HASH_BLOB>();
    search_thumbprint->hash_blob(hash_blob.get());

    // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
    if (!(pCertContext = CertFindCertificateInStore(
        hCertStore,
        X509_ASN_ENCODING,         // Use X509_ASN_ENCODING.
        0,                         // No dwFlags needed.
        CERT_FIND_SHA1_HASH,       // Find a certificate with a sha1 (thumbprint) that matches the string in the next parameter.
        hash_blob.get(),
        nullptr                    // NULL for the first call to the function. In all subsequent calls, it is the last pointer returned by the function.
    )))
    {
        uc::stringstream ss;
        ss << "Could not find certificate by thumbprint \"" << *search_thumbprint << "\"";
        log(ss);

        return false;
    }

    X509* x509 = nullptr;
    BIO* bio = nullptr;

    uc::string display_name{WSTR("unknown")};
    auto ier = get_display_name(pCertContext, display_name);

    // https://stackoverflow.com/a/11763389/1861346
    // https://github.com/DragonOsman/currency_converter/blob/master/root_certificate.hpp
    char* data = nullptr;
    std::string certificates;

    x509 = d2i_X509(nullptr, const_cast<const BYTE**>(&pCertContext->pbCertEncoded), pCertContext->cbCertEncoded);
    bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(bio, x509))
    {
        auto len = BIO_get_mem_data(bio, &data);
        if (certificates.empty())
        {
            certificates = { data, static_cast<std::size_t>(len) };

// TODO I am only adding a CA here, I also need to add the chain and actual certificate
            // Calls SSL_CTX_get_cert_store and X509_STORE_add_cert
            ctx_.add_certificate_authority(boost::asio::buffer(certificates.data(), certificates.size()), ec);
            if (ec)
            {
                uc::stringstream ss;
                ss << "Couldn't load certificate authority(1): Error = " << USTRING(ec.message());
                error(ss);
            }
            else
            {
                log(WSTR("Loading certificate authority"));
            }
        }
        else
        {
            certificates.append(data, static_cast<std::size_t>(len));
            ctx_.add_certificate_authority(boost::asio::buffer(certificates.data(), certificates.size()), ec);
            if (ec)
            {
                uc::stringstream ss;
                ss << "Couldn't load certificate authority.: Error = " << USTRING(ec.message());
                error(ss);
            }
            else
            {
                log(WSTR("Loading certificate authority."));
            }
        }
    }

    BIO_free(bio);
    X509_free(x509);

    {
        uc::stringstream ss;
        ss << "Found certificate \"" << display_name << "\" Thumbprint: \"" << *search_thumbprint << "\"";
        log(ss);
    }

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);

    return true;
}

auto CertificateHelper::load_server_certificate(
    uc::string const& store_name,
    Thumbprint const * const search_thumbprint
) -> bool
{
    {
        uc::stringstream ss;
        ss << "Attempting to load certificate \"" << *search_thumbprint << "\" from \"" << store_name << "\" store";
        log(ss);
    }

    boost::system::error_code ec;

    ctx_.set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2            |
        ssl::context::single_dh_use
    );

    if (!load_certificate_from_thumbprint(
        store_name,
        search_thumbprint,
        ec
    ))
    {
        return false;
    }

    if (ec)
    {
        uc::stringstream ss;
        ss << "Couldn't load certificate: error = " << USTRING(ec.message());
        error(ss);

        return false;
    }

    ctx_.set_password_callback([](std::size_t const, ssl::context_base::password_purpose)
    {
        return "test";
    });

    return true;
}


auto CertificateHelper::load_server_certificate() -> bool
{
    log(WSTR("Attempting to load static certificate"));

    // The certificate was generated from CMD.EXE on Windows 10 using:
    //
    // winpty openssl dhparam -out dh.pem 2048
    // winpty openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out cert.pem -subj "//C=US\ST=CA\L=Los Angeles\O=Beast\CN=www.example.com"
    std::string const cert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDaDCCAlCgAwIBAgIJAO8vBu8i8exWMA0GCSqGSIb3DQEBCwUAMEkxCzAJBgNV\n"
        "BAYTAlVTMQswCQYDVQQIDAJDQTEtMCsGA1UEBwwkTG9zIEFuZ2VsZXNPPUJlYXN0\n"
        "Q049d3d3LmV4YW1wbGUuY29tMB4XDTE3MDUwMzE4MzkxMloXDTQ0MDkxODE4Mzkx\n"
        "MlowSTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMS0wKwYDVQQHDCRMb3MgQW5n\n"
        "ZWxlc089QmVhc3RDTj13d3cuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA\n"
        "A4IBDwAwggEKAoIBAQDJ7BRKFO8fqmsEXw8v9YOVXyrQVsVbjSSGEs4Vzs4cJgcF\n"
        "xqGitbnLIrOgiJpRAPLy5MNcAXE1strVGfdEf7xMYSZ/4wOrxUyVw/Ltgsft8m7b\n"
        "Fu8TsCzO6XrxpnVtWk506YZ7ToTa5UjHfBi2+pWTxbpN12UhiZNUcrRsqTFW+6fO\n"
        "9d7xm5wlaZG8cMdg0cO1bhkz45JSl3wWKIES7t3EfKePZbNlQ5hPy7Pd5JTmdGBp\n"
        "yY8anC8u4LPbmgW0/U31PH0rRVfGcBbZsAoQw5Tc5dnb6N2GEIbq3ehSfdDHGnrv\n"
        "enu2tOK9Qx6GEzXh3sekZkxcgh+NlIxCNxu//Dk9AgMBAAGjUzBRMB0GA1UdDgQW\n"
        "BBTZh0N9Ne1OD7GBGJYz4PNESHuXezAfBgNVHSMEGDAWgBTZh0N9Ne1OD7GBGJYz\n"
        "4PNESHuXezAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCmTJVT\n"
        "LH5Cru1vXtzb3N9dyolcVH82xFVwPewArchgq+CEkajOU9bnzCqvhM4CryBb4cUs\n"
        "gqXWp85hAh55uBOqXb2yyESEleMCJEiVTwm/m26FdONvEGptsiCmF5Gxi0YRtn8N\n"
        "V+KhrQaAyLrLdPYI7TrwAOisq2I1cD0mt+xgwuv/654Rl3IhOMx+fKWKJ9qLAiaE\n"
        "fQyshjlPP9mYVxWOxqctUdQ8UnsUKKGEUcVrA08i1OAnVKlPFjKBvk+r7jpsTPcr\n"
        "9pWXTO9JrYMML7d+XRSZA1n3856OqZDX4403+9FnXCvfcLZLLKTBvwwFgEFGpzjK\n"
        "UEVbkhd5qstF6qWK\n"
        "-----END CERTIFICATE-----\n";

    std::string const key =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJ7BRKFO8fqmsE\n"
        "Xw8v9YOVXyrQVsVbjSSGEs4Vzs4cJgcFxqGitbnLIrOgiJpRAPLy5MNcAXE1strV\n"
        "GfdEf7xMYSZ/4wOrxUyVw/Ltgsft8m7bFu8TsCzO6XrxpnVtWk506YZ7ToTa5UjH\n"
        "fBi2+pWTxbpN12UhiZNUcrRsqTFW+6fO9d7xm5wlaZG8cMdg0cO1bhkz45JSl3wW\n"
        "KIES7t3EfKePZbNlQ5hPy7Pd5JTmdGBpyY8anC8u4LPbmgW0/U31PH0rRVfGcBbZ\n"
        "sAoQw5Tc5dnb6N2GEIbq3ehSfdDHGnrvenu2tOK9Qx6GEzXh3sekZkxcgh+NlIxC\n"
        "Nxu//Dk9AgMBAAECggEBAK1gV8uETg4SdfE67f9v/5uyK0DYQH1ro4C7hNiUycTB\n"
        "oiYDd6YOA4m4MiQVJuuGtRR5+IR3eI1zFRMFSJs4UqYChNwqQGys7CVsKpplQOW+\n"
        "1BCqkH2HN/Ix5662Dv3mHJemLCKUON77IJKoq0/xuZ04mc9csykox6grFWB3pjXY\n"
        "OEn9U8pt5KNldWfpfAZ7xu9WfyvthGXlhfwKEetOuHfAQv7FF6s25UIEU6Hmnwp9\n"
        "VmYp2twfMGdztz/gfFjKOGxf92RG+FMSkyAPq/vhyB7oQWxa+vdBn6BSdsfn27Qs\n"
        "bTvXrGe4FYcbuw4WkAKTljZX7TUegkXiwFoSps0jegECgYEA7o5AcRTZVUmmSs8W\n"
        "PUHn89UEuDAMFVk7grG1bg8exLQSpugCykcqXt1WNrqB7x6nB+dbVANWNhSmhgCg\n"
        "VrV941vbx8ketqZ9YInSbGPWIU/tss3r8Yx2Ct3mQpvpGC6iGHzEc/NHJP8Efvh/\n"
        "CcUWmLjLGJYYeP5oNu5cncC3fXUCgYEA2LANATm0A6sFVGe3sSLO9un1brA4zlZE\n"
        "Hjd3KOZnMPt73B426qUOcw5B2wIS8GJsUES0P94pKg83oyzmoUV9vJpJLjHA4qmL\n"
        "CDAd6CjAmE5ea4dFdZwDDS8F9FntJMdPQJA9vq+JaeS+k7ds3+7oiNe+RUIHR1Sz\n"
        "VEAKh3Xw66kCgYB7KO/2Mchesu5qku2tZJhHF4QfP5cNcos511uO3bmJ3ln+16uR\n"
        "GRqz7Vu0V6f7dvzPJM/O2QYqV5D9f9dHzN2YgvU9+QSlUeFK9PyxPv3vJt/WP1//\n"
        "zf+nbpaRbwLxnCnNsKSQJFpnrE166/pSZfFbmZQpNlyeIuJU8czZGQTifQKBgHXe\n"
        "/pQGEZhVNab+bHwdFTxXdDzr+1qyrodJYLaM7uFES9InVXQ6qSuJO+WosSi2QXlA\n"
        "hlSfwwCwGnHXAPYFWSp5Owm34tbpp0mi8wHQ+UNgjhgsE2qwnTBUvgZ3zHpPORtD\n"
        "23KZBkTmO40bIEyIJ1IZGdWO32q79nkEBTY+v/lRAoGBAI1rbouFYPBrTYQ9kcjt\n"
        "1yfu4JF5MvO9JrHQ9tOwkqDmNCWx9xWXbgydsn/eFtuUMULWsG3lNjfst/Esb8ch\n"
        "k5cZd6pdJZa4/vhEwrYYSuEjMCnRb0lUsm7TsHxQrUd6Fi/mUuFU/haC0o0chLq7\n"
        "pVOUFq5mW8p0zbtfHbjkgxyF\n"
        "-----END PRIVATE KEY-----\n";

    std::string const dh =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEArzQc5mpm0Fs8yahDeySj31JZlwEphUdZ9StM2D8+Fo7TMduGtSi+\n"
        "/HRWVwHcTFAgrxVdm+dl474mOUqqaz4MpzIb6+6OVfWHbQJmXPepZKyu4LgUPvY/\n"
        "4q3/iDMjIS0fLOu/bLuObwU5ccZmDgfhmz1GanRlTQOiYRty3FiOATWZBRh6uv4u\n"
        "tff4A9Bm3V9tLx9S6djq31w31Gl7OQhryodW28kc16t9TvO1BzcV3HjRPwpe701X\n"
        "oEEZdnZWANkkpR/m/pfgdmGPU66S2sXMHgsliViQWpDCYeehrvFRHEdR9NV+XJfC\n"
        "QMUk26jPTIVTLfXmmwU0u8vUkpR7LQKkwwIBAg==\n"
        "-----END DH PARAMETERS-----\n";

    ctx_.set_password_callback(
        [](std::size_t, ssl::context_base::password_purpose)
        {
            return "test";
        }
    );

    ctx_.set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2            |
        ssl::context::single_dh_use
    );

    ctx_.use_certificate_chain(
        boost::asio::buffer(cert.data(), cert.size())
    );

    ctx_.use_private_key(
        boost::asio::buffer(key.data(), key.size()),
        ssl::context::file_format::pem
    );

    ctx_.use_tmp_dh(
        boost::asio::buffer(dh.data(), dh.size())
    );

    return true;
}

auto CertificateHelper::log(uc::string const& mes)          -> void { log_(mes); };
auto CertificateHelper::log(uc::stringstream const& mes)    -> void { log_(mes.str()); };
auto CertificateHelper::error(uc::stringstream const& mes)  -> void { log_(mes.str()); };

auto CertificateHelper::require_client_verification(
    ssl::context& ctx,
    unsigned char const * const session_id_context,
    unsigned int const session_id_context_len,
    std::function<bool(bool const, ssl::verify_context&)> callback
) -> void
{
    log(WSTR("Requiring SSL client verification"));

    ctx_.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
    ctx_.set_verify_callback(callback);

    if (!SSL_CTX_set_session_id_context(ctx.native_handle(), session_id_context, session_id_context_len))
        log(WSTR("Could not set session ID context"));
}

// https://sourceforge.net/p/asio/mailman/message/30200852/
// set_verify_callback - the callback is called multiple times on each connection
auto ignore_client_certificate(
    bool const preverified,
    ssl::verify_context& vctx,
    std::function<void(uc::string const&)> log
) -> bool
{
    char subject_name[256];
    auto const cert = X509_STORE_CTX_get_current_cert(vctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, sizeof(subject_name));

    uc::stringstream ss;
    ss << "Ignoring client certificate, subject: " << subject_name;
    log(ss.str());

    return true;
}

} // namespace ex
