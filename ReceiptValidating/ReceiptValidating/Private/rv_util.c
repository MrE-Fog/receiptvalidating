//
//  rv_util.c
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/24/20.
//

#include "rv_util.h"
#include <openssl/asn1.h>

int rv_util_decode_int(size_t len, uint8_t *bytes, int isBigEndian)
{
    int value = 0;
    
    if (isBigEndian) {
        for (int i = 0; i < len; i ++) {
            value += (bytes[i] << (8*(len - i - 1)));
        }
    } else {
        for (int i = 0; i < len; i ++) {
            value += (bytes[i] << (8*i));
        }
    }
    
    return value;
}

void rv_util_print_bytes_with_tag(char *tag, size_t buffer_len, uint8_t *buffer)
{
    printf("%s: ", tag);
    
    for(size_t i = 0; i < buffer_len; i++) {
        
        printf("%02X", buffer[i]);
    }
    
    printf("\n");
}
