#include "ex/ex_config.h"

#include "ex/Thumbprint.h"

namespace Ex
{

Thumbprint::Thumbprint(value_type const * const ptr, size_type const hash_size)
    : impl_(new ThumbprintImpl(ptr, hash_size))
{ }

Thumbprint::Thumbprint()
    : impl_(new ThumbprintImpl())
{ }

Thumbprint::Thumbprint(std::string const& thumbprint_str)
    : impl_(new ThumbprintImpl(thumbprint_str))
{ }

Thumbprint::ThumbprintImpl::ThumbprintImpl(value_type const * const ptr, size_type const hash_size)
    : bin_data(ptr, ptr + hash_size)
{ }

Thumbprint::ThumbprintImpl::ThumbprintImpl(std::string const& thumbprint_str)
{
    // There's a way to do this with CryptStringToBinary, but I can't seem to
    // get it working.

    bin_data.reserve(thumbprint_str.length() / 2); // Each character represents a nibble

    for (size_type i = 0; i < thumbprint_str.length(); i += 2)
    {
        unsigned int c1, c2;
        {
            std::stringstream ss;
            ss << std::hex << thumbprint_str[i];
            ss >> c1;
            c1 = (c1 << 4) & 0x000000F0; // shift left
        }
        {
            std::stringstream ss;
            ss << std::hex << thumbprint_str[i+1];
            ss >> c2;
        }

        auto cf = static_cast<value_type>(c1 | c2);
        bin_data.push_back(cf);
    }
}

Thumbprint::~Thumbprint()
{
    delete impl_;
}

auto Thumbprint::operator=(Thumbprint const& other) -> Thumbprint&
{
    impl_->bin_data = other.impl_->bin_data;
    return *this;
}

auto Thumbprint::operator==(Thumbprint const& other) const -> bool
{
    return impl_->bin_data == other.impl_->bin_data;
}

auto operator<<(std::ostream& out, Thumbprint const& dt) -> std::ostream&
{
    out << dt.impl_->str();
    return out;
}

auto operator<<(std::wostream& out, Thumbprint const& dt) -> std::wostream&
{
    out << std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(dt.impl_->str());
    return out;
}

auto Thumbprint::ThumbprintImpl::str() const -> std::string
{
    // Think of this as printing a number one digit at a time
    // So for the number 23,
    // - first zero out everything but the tens, leaving us with 20,
    // - then shift it down an order of magnitude, leaving us with 2.
    // - Then, return to the original number, and zero out everything
    //   except the ones, leaving us with 3

    std::stringstream out;
    for (size_type i = 0; i < size(); ++i)
        out << std::hex << ((bin_data[i] & 0x000000F0) >> 4) << (bin_data[i] & 0x000000F);

    return out.str();
}

auto Thumbprint::ThumbprintImpl::data() const noexcept -> const value_type*
{
    return bin_data.data();
}

auto Thumbprint::ThumbprintImpl::hash_blob(CRYPT_HASH_BLOB * const blob) -> void
{
    blob->cbData = size();
    blob->pbData = reinterpret_cast<BYTE*>(&bin_data[0]);
}

} // /namespace Ex

/* vim: set ts=4 sw=4 tw=0 ff=dos et :*/
