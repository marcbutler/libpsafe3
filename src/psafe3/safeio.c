/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include "util.h"

#include "safeio.h"

static const char MAGIC[] = {'P', 'W', 'S', '3'};

static const BYTE DBEND[] = {'P', 'W', 'S', '3', '-', 'E', 'O', 'F',
                             'P', 'W', 'S', '3', '-', 'E', 'O', 'F'};

                      