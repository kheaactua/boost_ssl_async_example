#include "ex/pch.h"

#include "ex/certificate_helpers.h"

#include "ex/Thumbprint.h"

namespace Ex
{

auto get_property(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId,
    std::function<void(void*, DWORD)> setter
) -> int
{
    void*  pvData;
    DWORD  cbData;

    if (CertGetCertificateContextProperty(
        pCertContext,
        dwPropId,
        NULL,
        &cbData)
    )
    {
        if (!(pvData = (void*)malloc(cbData)))
        {
            return -1;
        }

        if (CertGetCertificateContextProperty(
            pCertContext,
            dwPropId,
            pvData,
            &cbData))
        {
            setter(pvData, cbData);
        }
        else
        {
            return -2;
        }
    }
    else
    {
        return -3;
    }
    return 0;
}

auto get_thumbprint(
    PCCERT_CONTEXT pCertContext,
    Ex::Thumbprint& thumbprint
) -> int
{
    return get_property(
        pCertContext,
        CERT_SHA1_HASH_PROP_ID,
        [&thumbprint](void* pvData, DWORD cbData)
        {
            Ex::Thumbprint t(reinterpret_cast<char*>(pvData), cbData);
            thumbprint = t;
        }
    );
}

auto get_display_name(
    PCCERT_CONTEXT pCertContext,
    std::wstring& display_name
) -> int
{
    return get_property(
        pCertContext,
        CERT_FRIENDLY_NAME_PROP_ID,
        [&display_name](void* pvData, DWORD cbData)
        {
            std::wstringstream ss;
            ss << static_cast<wchar_t*>(pvData);
            ss >> display_name;
        }
    );
}

auto load_certificate_from_thumbprint(
    std::wstring const& store_name,
    Ex::Thumbprint const * const search_thumbprint,
    boost::asio::ssl::context& ctx,
    boost::system::error_code& ec,
    std::function<void(std::wstring const&)> out,
    std::function<void(std::wstring const&)> err
) -> bool
{
    auto found = false;
    HCERTSTORE      hCertStore;
    PCCERT_CONTEXT  pCertContext = nullptr;
    wchar_t         pszNameString[256];
    DWORD           dwPropId = 0;

    //-------------------------------------------------------------------
    // Open a system certificate store.

    if (hCertStore = CertOpenSystemStore(NULL, store_name.c_str()))
    {
        out(L"The " + store_name + L" store has been opened");
    }
    else
    {
        // If the store was not opened, exit to an error routine.
        err(L"The '" + store_name + L"' store was not opened.");
    }

    //-------------------------------------------------------------------
    // Use CertEnumCertificatesInStore to get the certificates
    // from the open store. pCertContext must be reset to
    // NULL to retrieve the first certificate in the store.

    pCertContext = nullptr;

    Ex::Thumbprint test_tp;
    while (pCertContext = CertEnumCertificatesInStore(
            hCertStore,
            pCertContext
        )
    )
    {
        if (CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            pszNameString,
            128)
        )
        {
            // Continue
        }
        else
        {
            err(L"CertGetName failed.");
        }

        auto ier = get_thumbprint(pCertContext, test_tp);
        if (0 != ier)
        {
            err(L"Could not find thumbnail on specified certificate");
            continue;
        }

        if (test_tp == *search_thumbprint)
        {
            found = true;
            break;
        }
    }

    if (found)
    {
        X509* x509 = nullptr;
        BIO* bio = nullptr;

        std::wstring display_name{L"unknown"};
        auto ier = get_display_name(pCertContext, display_name);

        // https://stackoverflow.com/a/11763389/1861346
        // https://github.com/DragonOsman/currency_converter/blob/master/root_certificate.hpp
        char* data = nullptr;
        std::string certificates;

        x509 = d2i_X509(nullptr, const_cast<const BYTE**>(&pCertContext->pbCertEncoded), pCertContext->cbCertEncoded);
        bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_X509(bio, x509))
        {
            out(L"PEM_write_bio_X509");
            auto len = BIO_get_mem_data(bio, &data);
            if (certificates.size() == 0)
            {
                certificates = { data, static_cast<std::size_t>(len) };

                // Calls SSL_CTX_get_cert_store and X509_STORE_add_cert
                ctx.add_certificate_authority(boost::asio::buffer(certificates.data(), certificates.size()), ec);
                if (ec)
                {
                    std::wstringstream ss;
                    ss << "Couldn't load certificate (1): error = " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(ec.message());
                    err(ss.str());
                }
                else
                {
                    out(L"Loading certificate (1)");
                }
            }
            else
            {
                certificates.append(data, static_cast<std::size_t>(len));
                ctx.add_certificate_authority(boost::asio::buffer(certificates.data(), certificates.size()), ec);
                if (ec)
                {
                    std::wstringstream ss;
                    ss << "Couldn't load certificate (2): error = " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(ec.message());
                    err(ss.str());
                }
                else
                {
                    out(L"Loading certificate (2)");
                }
            }
        }

        BIO_free(bio);
        X509_free(x509);

        {
            std::wstringstream log;
            log << L"Found certificate '" << display_name << "' TP: '" << test_tp << "'";
            out(log.str());
        }
    }

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);

    return found;
}

auto load_server_certificate(boost::asio::ssl::context& ctx) -> void
{
    std::wcout << L"Attempting to load certificate from store\n";
    boost::system::error_code ec;

    ctx.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2            |
        boost::asio::ssl::context::single_dh_use
    );

    Ex::Thumbprint tp("ffe1e9a5f5b558f7f84808647680fdc77844e591"); // boosts
    load_certificate_from_thumbprint(
        L"MY",
        &tp,
        ctx,
        ec,
        [](auto const& mes) { std::wcout << mes << "\n"; },
        [](auto const& mes) { std::wcerr << L"Error: " << mes << "\n"; }
    );

    if (ec)
    {
        std::wcerr << "Couldn't load certificate: error = " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(ec.message());

        throw boost::system::system_error{ec};
    }

    ctx.set_password_callback(
        [](std::size_t, boost::asio::ssl::context_base::password_purpose)
        {
            return "test";
        }
    );
}

auto load_static_server_certificate(boost::asio::ssl::context& ctx) -> void
{
    std::wcout << L"Attempting to load static certificate\n";

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

    ctx.set_password_callback(
        [](std::size_t, boost::asio::ssl::context_base::password_purpose)
        {
            return "test";
        }
    );

    ctx.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2            |
        boost::asio::ssl::context::single_dh_use
    );

    ctx.use_certificate_chain(
        boost::asio::buffer(cert.data(), cert.size())
    );

    ctx.use_private_key(
        boost::asio::buffer(key.data(), key.size()),
        boost::asio::ssl::context::file_format::pem
    );

    ctx.use_tmp_dh(
        boost::asio::buffer(dh.data(), dh.size())
    );
}

} // namespace ex
