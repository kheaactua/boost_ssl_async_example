#ifndef THUMBPRINT_H_OLV7PBLF
#define THUMBPRINT_H_OLV7PBLF

#include <vector>

namespace Ex
{

/**
 * \brief
 * Class to help work with SHA1 thumbprints.  This copies the thumbprint
 * into in self
 *
 * \remarks
 * If we want to avoid the read, we could write a custom allocator that would
 * map the memory to the pointer,  But then you'd have to be very careful as
 * something else then manages the memory.  See
 * https://stackoverflow.com/a/21918950/1861346 for an example
 *
 * \remarks
 * While SHA1's are always 20
 * bytes, at the time of writing I'm not sure if Thumbprints are always SHA1,
 * also, there are other values we might want to print.  On top of all this,
 * because we deal with a C interface, we only know the length at runtime, so
 * we'll use the heap (vector) instead of the stack (array) and won't template
 * this on the size */
class Thumbprint : public std::vector<char>
{
   public:
       /** Copy a SHA1 from a pointer */
        Thumbprint(Thumbprint::value_type const * const ptr, std::vector<Thumbprint::value_type>::size_type const hash_size);

        /* Copy a SHA1 from a string */
        Thumbprint(std::string const& thumbprint);

        Thumbprint();

        /*Thumbprint(Thumbprint const& b) = default;
        Thumbprint(Thumbprint&& b) = default;*/

   private:
     template<class OStream>
     friend auto operator<<(OStream& out, Thumbprint const& dt) -> OStream&;
};

template<class OStream>
auto operator<<(OStream& out, Thumbprint const& tp) -> OStream&
{
    // Think of this as printing a number one digit at a time
    // So for the number 23,
    // - first zero out everything but the tens, leaving us with 20,
    // - then shift it down an order of magnitude, leaving us with 2.
    // - Then, return to the original number, and zero out everything
    //   except the ones, leaving us with 3

    for (Thumbprint::size_type i = 0; i < tp.size(); ++i)
        out << std::hex << ((tp[i] & 0x000000F0) >> 4) << (tp[i] & 0x000000F);

    return out;
}

} // /namespace Ex


#endif /* end of include guard: THUMBPRINT_H_OLV7PBLF */

/* vim: set ts=4 sw=4 tw=0 et ff=dos :*/
