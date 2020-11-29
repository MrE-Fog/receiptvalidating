//
//  RVReceipt.h
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/24/20.
//

#import <Foundation/Foundation.h>
#import "RVProductReceipt.h"

NS_ASSUME_NONNULL_BEGIN

@interface RVReceipt : NSObject

@property (nonatomic, strong) NSString *bundleId;
@property (nonatomic, strong) NSData *bundleIdData;
@property (nonatomic, strong) NSString *bundleVersion;
@property (nonatomic, strong) NSData *guid;
@property (nonatomic, strong) NSData *opaque;

@property (nonatomic, strong, nullable) NSString *appVersion;
@property (nonatomic, strong, nullable ) NSDate *createdDate;
@property (nonatomic, strong, nullable) NSDate *expirationDate;

@property (nonatomic, strong) NSArray<RVProductReceipt> *iapReceipts;

@end

NS_ASSUME_NONNULL_END
