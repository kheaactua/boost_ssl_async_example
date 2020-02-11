#include "ex/pch.h"

#include "ex/ex.h"
#include "ex/Session.h"
#include "ex/Listener.h"

// Normally I'd explicitly instantiate the classes I want to use (normally this
// would be a lib), but this results in a /bigobj exception on compiling
namespace Ex
{
    template class Listener<Types::ssl_stream, Types::ssl_context>;
    template class Session<Types::ssl_stream,  Types::ssl_context>;

    // Not used
    // template class Listener<Types::text_stream, Types::plain_text_context>;
    // template class Session<Types::text_stream,  Types::plain_text_context>;
}
