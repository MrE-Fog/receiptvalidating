//
//  NSData+Hex.m
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/24/20.
//

#import "NSData+Hex.h"

@implementation NSData (Hex)

+ (NSData *)fromHexString:(NSString *)string {
    
    string = [string lowercaseString];
    NSMutableData *data= [NSMutableData new];
    
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i = 0;
    int length = (int)string.length;
    
    while (i < length - 1) {
        
        char c = [string characterAtIndex:i++];
        
        if (c < '0' || (c > '9' && c < 'a') || c > 'f') {
         
            continue;
        }
        
        byte_chars[0] = c;
        byte_chars[1] = [string characterAtIndex:i++];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    
    return data;
}

- (NSString *)toHexString {
    
    const unsigned char *bytes = (const unsigned char *)self.bytes;
    NSMutableString *hex = [NSMutableString new];
    
    for (NSInteger i = 0; i < self.length; i++) {
        
        [hex appendFormat:@"%02X", bytes[i]];
    }
    
    return [hex copy];
}

- (NSData *)reversed {
    
    NSMutableData *reversed = [[NSMutableData alloc] init];
    for(int i = (int)self.length - 1; i >=0; i--){
        [reversed appendBytes: &self.bytes[i] length:1];
    }
    return [reversed copy];
}

@end
