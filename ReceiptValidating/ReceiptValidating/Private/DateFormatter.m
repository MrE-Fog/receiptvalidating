//
//  DateFormatter.m
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/24/20.
//

#import "DateFormatter.h"

@implementation DateFormatter

- (instancetype)init
{
    self = [super init];
    if (self) {
        
        [self setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"]];
        [self setDateFormat:@"yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"];
        [self setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
    }
    return self;
}

@end
