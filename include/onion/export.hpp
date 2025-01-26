#pragma once

#if defined(ONION_SHARED_LIBS)
#    if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#        if defined(ONION_BUILD_SHARED_LIBS)
#            define ONION_API __declspec(dllexport)
#        else
#            define ONION_API __declspec(dllimport)
#        endif
#    else
#        define ONION_API __attribute__((visibility("default")))
#    endif
#else
#    define ONION_API
#endif
