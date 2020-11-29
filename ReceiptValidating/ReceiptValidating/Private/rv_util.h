//
//  rv_util.h
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/24/20.
//

#ifndef rv_util_h
#define rv_util_h

#include <stdio.h>

int rv_util_decode_int(size_t len, uint8_t *bytes, int isBigEndian);
void rv_util_print_bytes_with_tag(char *tag, size_t buffer_len, uint8_t *buffer);

#endif /* rv_util_h */
