#if !defined(__MHASH_H)
#define __MHASH_H

#ifdef VERSION
#  define __MHASH_VERSION_KLUDGE VERSION
#  undef VERSION
#endif

#include <mutils/mincludes.h>
#include <mutils/mglobal.h>
#include <mutils/mtypes.h>
#include <mutils/mutils.h>
#include <mutils/mhash.h>

#define __MHASH_VERSION VERSION
#undef VERSION
#ifdef __MHASH_VERSION_KLUDGE
#  define VERSION __MHASH_VERSION_KLUDGE
#endif

#endif

