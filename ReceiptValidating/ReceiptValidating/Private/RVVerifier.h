//
//  RVVerifier.h
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/25/20.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RVVerifier : NSObject

+ (nullable NSData *)readContentsOfReceipt:(NSData *)receipt
                           rootCertificate:(NSData *)rootCertificate error:(NSError **)error;

+ (BOOL)verifyHashWithVendorId:(NSData *)vendorId
               receiptOpaqueId:(NSData *)receiptOpaqueId
               receiptBundleIdData:(NSData *)receiptBundleIdData
                   receiptHash:(NSData *)receiptHash;
@end

NS_ASSUME_NONNULL_END
