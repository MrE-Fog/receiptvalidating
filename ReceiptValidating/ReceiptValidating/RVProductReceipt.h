//
//  RVProductReceipt.h
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/24/20.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol RVProductReceipt;

@interface RVProductReceipt : NSObject

@property (nonatomic, strong) NSNumber *quantity;
@property (nonatomic, strong) NSString *productId;
@property (nonatomic, strong) NSString *transactionId;
@property (nonatomic, strong) NSString *originalTransactionId;
@property (nonatomic, strong) NSDate *purchaseDate;
@property (nonatomic, strong) NSDate *originalPurchaseDate;
@property (nonatomic, strong) NSNumber *webOrderId;
@property (nonatomic, strong, nullable) NSDate *expiryDate;
@property (nonatomic, strong, nullable) NSDate *cancelledDate;

@end

NS_ASSUME_NONNULL_END
