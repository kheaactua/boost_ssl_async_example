#ifndef PCH_H_OQ6N54XI
#define PCH_H_OQ6N54XI

// Prevent Windows.h from defining a 'max' macro
#define NOMINMAX

// Fix no_init_all error
#if (_MSC_VER >= 1915)
#define no_init_all deprecated
#endif



#endif /* end of include guard: PCH_H_OQ6N54XI */