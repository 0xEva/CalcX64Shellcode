#include "peparser.h"

#ifdef _WIN64
#  define ADDR DWORDLONG
#else
#define   ADDR DWORD
#endif

#define RVATOVA( base, offset ) ( (ADDR)base + (ADDR)offset )


ADDR MyGetNTDLLProcAddress(
    IN const char* procName
);

