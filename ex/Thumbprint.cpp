#include "pch.h"

#include "ex/Thumbprint.h"

namespace Ex
{

Thumbprint::Thumbprint(Thumbprint::value_type const * const ptr, std::vector<Thumbprint::value_type>::size_type const hash_size)
    : std::vector<Thumbprint::value_type>(ptr, ptr + hash_size)
{ }

Thumbprint::Thumbprint()
    : std::vector<Thumbprint::value_type>()
{ }

Thumbprint::Thumbprint(std::string const& thumbprint_str)
{
    reserve(thumbprint_str.length()/2); // Each character represents a nibble

    auto const wt = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(thumbprint_str);

    for (Thumbprint::size_type i = 0; i < thumbprint_str.length(); i += 2)
    {
        //Thumbprint::value_type c1, c2;
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

        char cf = c1 | c2;

        push_back(c1 | c2);
    }
}

} // /namespace Ex

/* vim: set ts=4 sw=4 tw=0 ff=dos et :*/
