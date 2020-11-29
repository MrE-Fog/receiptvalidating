//
//  RVUtility.h
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/23/20.
//

#import <Foundation/Foundation.h>
#import "RVReceipt.h"

NS_ASSUME_NONNULL_BEGIN

@interface RVUtility : NSObject

/**
 @brief validates IAP receipt aginst apple root certificate
 @param receiptData - app receipt file contents
 @param rootCertificate - apple root certificate file contents
 @return receipt model or nil (throws error)
 */
+ (nullable RVReceipt *)inspectReceiptData:(NSData *)receiptData
                       rootCertificateData:(NSData *)rootCertificate
                                  vendorId:(NSData *)vendorId
                                  bundleId:(NSString *)bundleId
                                     error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
