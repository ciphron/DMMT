#ifndef DMMT_TYPES_H
#define DMMT_TYPES_H

#include <stdlib.h>
#include <stdint.h> /* uint8_t etc... */

enum {
    DMMT_STAT_OK = 0,
    DMMT_STAT_UNSUPPORTED_CIPHER= -1,
    DMMT_STAT_UNSUPPORTED_CIPHER_PARAMS,
    DMMT_STAT_UNDERSIZED_BUFFER,
    DMMT_STAT_INTERNAL_ERROR,
    DMMT_STAT_BELOW_THRESHOLD
};

typedef int dmmt_stat_t;

#endif
