#ifndef THUMBPRINT_H_OLV7PBLF
#define THUMBPRINT_H_OLV7PBLF

#include "ex_config.h"

#include <ios>
#include <vector>

#include <wincrypt.h>

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
class DLLEXPORT Thumbprint
{
   public:
    using value_type = BYTE;
    using size_type = std::vector<value_type>::size_type;

    /** Copy a SHA1 from a pointer */
    Thumbprint(value_type const * const ptr, size_type const hash_size);

    /* Copy a SHA1 from a string */
    explicit Thumbprint(std::string const& thumbprint);

    Thumbprint();

   ~Thumbprint();

    auto operator=(Thumbprint const& other) -> Thumbprint&;
    auto operator==(Thumbprint const& other) const -> bool;

    auto size() const noexcept -> size_type { return impl_->size(); }

    auto data() const noexcept -> const value_type* { return impl_->data(); }

    auto hash_blob(CRYPT_HASH_BLOB * const blob) const -> void { impl_->hash_blob(blob); };

   private:

    struct ThumbprintImpl
    {
        /** Copy a SHA1 from a pointer */
        ThumbprintImpl(value_type const * const ptr, size_type const hash_size);

        /* Copy a SHA1 from a string */
        explicit ThumbprintImpl(std::string const& thumbprint);

        ThumbprintImpl() = default;

        std::vector<value_type> bin_data;

        auto size() const noexcept -> size_type { return bin_data.size(); }

        auto str() const -> std::string;

        auto data() const noexcept -> const value_type*;

        auto hash_blob(CRYPT_HASH_BLOB * const blob) -> void;
    };

    // I can't use an std::unqiue_ptr or std::vector here, or anything std
    // without risking dll interface issues (and warnings)
    ThumbprintImpl* impl_ = nullptr;

    friend auto operator<<(std::ostream& out,  Thumbprint const& dt) -> std::ostream&;
    friend auto operator<<(std::wostream& out, Thumbprint const& dt) -> std::wostream&;
};

} // /namespace Ex

#endif /* end of include guard: THUMBPRINT_H_OLV7PBLF */

/* vim: set ts=4 sw=4 tw=0 et ff=dos :*/
