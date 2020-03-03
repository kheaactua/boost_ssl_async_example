# Overview

This example application runs a HTTPS (but was pulled from a project that also required an HTTP server.)
The structure of the code was based on Boost's
[http_server_async_ssl.cpp](https://www.boost.org/doc/libs/1_72_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp)
and the non-SSL version
[http_server_async.cpp](https://www.boost.org/doc/libs/1_72_0/libs/beast/example/http/server/async/http_server_async.cpp)
example, but has been modified in order to be used as a simulator, _e.g._ to
allow the capability of downstream callers to close the socket and disabled all
non-POST requests.

The certificate code was modeled after [Example C Program: Listing the Certificates in a Store](https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-listing-the-certificates-in-a-store), [SO: Can OpenSSL on Windows use the system certificate store?](https://stackoverflow.com/a/11763389/1861346), [DragonOsman / currency_converter](https://github.com/DragonOsman/currency_converter/blob/master/root_certificate.hpp)

# Build

```sh
mkdir bld
cd bld
cmake -G"Visual Studio 15 2017 Win64" -DVCPKG_TARGET_TRIPLET=x64-windows -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ..
cmake --build .
```

## Create Certtificate file
```
openssl pkcs12 -inkey ~/tmp/key.pem -in ~/tmp/cert.pem -name "Boost" -export -out ~/tmp/boost.pfx
```

# Usage

Using this requires a `Listener` be created.  In this project this is a member
of `DataHandler`.  One this is created, the `Listener` should be provided with
lambdas to handle failure conditions and post requests.  For example,

```c++
// Set up post event
listener_->on_post([this](
    unsigned const version,
    boost::string_view req_ip,
    std::string const& body
)
{
    PostMessage("Received " + std::to_string(body.length()) + " characters from " + req_ip.to_string());
});
```

# Issues and Outstanding Items

- Certificate is hard-coded (see [SO question](https://stackoverflow.com/q/60180688/1861346))

# Code Comments

One specific note about the `Listener`/`Session`.  At first these had concrete
implementations, but when the requirement for an http server was added these two
classes were templated in order to support both cases.  While this works, in
hind sight it may have been better if two Session classes were created, as the
current implementation wraps most of Session's members with `enable_if`s,
rendering the class to almost be duplicated within it self.

# Refereces

- [OpenSSL Examples Wserver2.c](https://github.com/Andersbakken/openssl-examples/blob/master/wserver2.c)
- [http_server_async_ssl.cpp](https://www.boost.org/doc/libs/1_72_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp)
- [http_server_async.cpp](https://www.boost.org/doc/libs/1_72_0/libs/beast/example/http/server/async/http_server_async.cpp)
