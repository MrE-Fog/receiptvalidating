//
//  RVUtility.m
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/23/20.
//

#import "RVUtility.h"
#import "NSData+Hex.h"
#import "RVVerifier.h"
#import "DateFormatter.h"

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

#include "rv_util.h"
#include "rv_defines.h"

@implementation RVUtility

+ (nullable RVReceipt *)inspectReceiptData:(NSData *)receiptData
                       rootCertificateData:(NSData *)rootCertificate
                                  vendorId:(NSData *)vendorId
                                  bundleId:(NSString *)bundleId
                                     error:(NSError **)error {
    
    NSError *inspectError;
    NSData *contents = [RVVerifier readContentsOfReceipt:receiptData rootCertificate:rootCertificate error:&inspectError];
    
    if (inspectError != nil) {
        *error = inspectError;
        return nil;
    }
    
    RVReceipt *receipt = [self parseReceiptContents:contents error:&inspectError];
    
    if (inspectError != nil) {
        *error = inspectError;
        return nil;
    }
    
    if (receipt.bundleId == nil || receipt.opaque == nil || receipt.guid == nil) {
        
        // errro
        return nil;
    }
    
    if (![bundleId isEqualToString:receipt.bundleId]) {

        // error
        return nil;
    }

    BOOL hasValidHash = [RVVerifier verifyHashWithVendorId:vendorId
                                           receiptOpaqueId:receipt.opaque
                                           receiptBundleIdData:receipt.bundleIdData
                                               receiptHash:receipt.guid];
    
    if (!hasValidHash) {
        // error
        return nil;
    }
    
    return receipt;
}

+ (nullable RVReceipt *)parseReceiptContents:(NSData *)receiptContents error:(NSError **)error {
    
    RVReceipt *receipt = [RVReceipt new];
    NSMutableArray<RVProductReceipt> *iapReceipts = (NSMutableArray<RVProductReceipt> *)[NSMutableArray new];
    
    NSDateFormatter *dateFormatter = [DateFormatter new];
    const uint8_t *p = receiptContents.bytes;
    const uint8_t *end = p + receiptContents.length;
    
    int type = 0;
    int xclass = 0;
    long length = 0;
    
    int attr_type = 0;
    int attr_version = 0;
    
    ASN1_get_object(&p, &length, &type, &xclass, end - p);
    if (type != V_ASN1_SET) { return nil; }
    
    while (p < end) {
        
        ASN1_get_object(&p, &length, &type, &xclass, end - p);
        if (type != V_ASN1_SEQUENCE) { return nil; }
        const uint8_t *seq_end = p + length;
        
        // Attribute type
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        if (type == V_ASN1_INTEGER && length == 1) {
            attr_type = p[0];
        } else {
            // TODO:
        }
        p += length;
        
        // Attribute version
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        if (type == V_ASN1_INTEGER && length == 1) {
            attr_version = p[0];
        } else {
            // TODO:
        }
        p += length;
        
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        
        switch (attr_type) {
                
            case ATT_TYPE_BUNDLE_ID: {
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.bundleId = [self readASN1StringAtObjectAddress:p objectLength:length];
                    receipt.bundleIdData = [NSData dataWithBytes:p length:length];
                }
            } break;
                
            case ATT_TYPE_BUNDLE_VERSION: {
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.bundleVersion = [self readASN1StringAtObjectAddress:p objectLength:length];
                }
            } break;
                
            case ATT_TYPE_OPAQUE: {
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.opaque = [NSData dataWithBytes:p length:length];
                }
            }
                break;
            
            case ATT_TYPE_GUID: {
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.guid = [NSData dataWithBytes:p length:length];
                }
            }
                break;
                
            case ATT_TYPE_RECEIPT_CREATION_DATE: {
                if (type == V_ASN1_OCTET_STRING) {
                    NSString *value = [self readASN1StringAtObjectAddress:p objectLength:length];
                    if (value != nil) {
                        receipt.createdDate = [dateFormatter dateFromString:value];
                    }
                }
            }
                break;
                
            case ATT_TYPE_RECEIPT_EXPIRATOPM_DATE: {
                if (type == V_ASN1_OCTET_STRING) {
                    NSString *value = [self readASN1StringAtObjectAddress:p objectLength:length];
                    if (value != nil) {
                        receipt.expirationDate = [dateFormatter dateFromString:value];
                    }
                }
            }
                break;
                
            case ATT_TYPE_ORIGINAL_APP_VERSION: {
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.appVersion = [self readASN1StringAtObjectAddress:p objectLength:length];
                }
            }
                
            case ATT_TYPE_RECEIPT: {
                if (type == V_ASN1_OCTET_STRING) {
                    RVProductReceipt *productReceipt = [self parseProductReceipt:p objectLength:length];
                    if (productReceipt != nil) {
                        [iapReceipts addObject:productReceipt];
                    }
                }
            }
                break;
                
            default:
                //printf("skip attribute type: %d\n", attr_type);
                break;
        }
                        
        p += length;
    }
        
    receipt.iapReceipts = [iapReceipts copy];
    
    return receipt;
}

+ (nullable RVProductReceipt *)parseProductReceipt:(const unsigned char *)objectAddress objectLength:(NSUInteger)objectLength {
    
    RVProductReceipt *receipt = [RVProductReceipt new];

    NSDateFormatter *dateFormatter = [DateFormatter new];
    const uint8_t *p = objectAddress;
    const uint8_t *end = p + objectLength;
    
    int type = 0;
    int xclass = 0;
    long length = 0;
    
    int attr_type = 0;
    int attr_version = 0;
    
    ASN1_get_object(&p, &length, &type, &xclass, objectLength);
    if (type != V_ASN1_SET) { return nil; }
        
    while (p < end) {
        
        ASN1_get_object(&p, &length, &type, &xclass, end - p);
        if (type != V_ASN1_SEQUENCE) { return nil; }
        
        const uint8_t *seq_end = p + length;
        
        // Attribute type
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        if (type == V_ASN1_INTEGER) {
            attr_type = rv_util_decode_int(length, (uint8_t *)p, 1);
        }
        p += length;
        
        // Attribute version
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        if (type == V_ASN1_INTEGER) {
            attr_version = p[0];
        }
        p += length;
        
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        
        switch (attr_type) {
                
            case INAPP_TYPE_QUANTITY:
                if (type == V_ASN1_OCTET_STRING) {
                    long value = [self readASN1LongAtObjectAddress:p objectLength:length];
                    receipt.quantity = @(value);
                }
                break;
            case INAPP_TYPE_PROD_ID:
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.productId = [self readASN1StringAtObjectAddress:p objectLength:length];
                }
                break;
                
            case INAPP_TYPE_TRA_ID:
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.transactionId = [self readASN1StringAtObjectAddress:p objectLength:length];
                }
                break;
                
            case INAPP_TYPE_PURCHASE_DATE:
                if (type == V_ASN1_OCTET_STRING) {
                    NSString *value = [self readASN1StringAtObjectAddress:p objectLength:length];
                    if (value != nil) {
                        receipt.purchaseDate = [dateFormatter dateFromString:value];
                    }
                }
                break;
            case INAPP_TYPE_ORG_TRA_ID:
                if (type == V_ASN1_OCTET_STRING) {
                    receipt.originalTransactionId = [self readASN1StringAtObjectAddress:p objectLength:length];
                }
                break;
            case INAPP_TYPE_ORG_PURCHASE_DATE:
                if (type == V_ASN1_OCTET_STRING) {
                    NSString *value = [self readASN1StringAtObjectAddress:p objectLength:length];
                    if (value != nil) {
                        receipt.originalPurchaseDate = [dateFormatter dateFromString:value];
                    }
                }
                break;
            
            case INAPP_TYPE_SUB_EXPIRY_DATE:
                if (type == V_ASN1_OCTET_STRING) {
                    NSString *value = [self readASN1StringAtObjectAddress:p objectLength:length];
                    if (value != nil) {
                        receipt.expiryDate = [dateFormatter dateFromString:value];
                    }
                }
                break;
            case INAPP_TYPE_WEB_ORDER:
                if (type == V_ASN1_OCTET_STRING) {
                    long value = [self readASN1LongAtObjectAddress:p objectLength:length];
                    receipt.webOrderId = @(value);
                }
                break;
                
            case INAPP_TYPE_CANCEL_DATE:
                if (type == V_ASN1_OCTET_STRING) {
                    NSString *value = [self readASN1StringAtObjectAddress:p objectLength:length];
                    if (value != nil) {
                        receipt.cancelledDate = [dateFormatter dateFromString:value];
                    }
                }
                break;
        }
        
        p += length;
    }
    
    return receipt;
}

+ (nullable NSString *)readASN1StringAtObjectAddress:(const unsigned char *)objectAddress objectLength:(NSUInteger)objectLength {
    
    // NOTE: objectLength - denotes the entire ASN1 object length (Identifier || Length || Value)
    // Calling ASN1_get_object on this object will shift ptr to the beginning of value and will extract actual value length!
    
    int type = 0;
    int xclass = 0;
    long valueLength = 0;
    ASN1_get_object(&objectAddress, &valueLength, &type, &xclass, objectLength);
    
    if (type == V_ASN1_UTF8STRING && valueLength > 0) {
        
        NSData *data = [NSData dataWithBytes:objectAddress length:valueLength];
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        
    } else if (type == V_ASN1_IA5STRING && valueLength > 0) {
        
        NSData *data = [NSData dataWithBytes:objectAddress length:valueLength];
        return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
        
    } else {
    
        return nil;
    }
}

+ (long)readASN1LongAtObjectAddress:(const unsigned char *)objectAddress objectLength:(NSUInteger)objectLength {
    
    int type = 0;
    int xclass = 0;
    long valueLength = 0;
    ASN1_get_object(&objectAddress, &valueLength, &type, &xclass, objectLength);
    
    long value = 0;
    NSData *data = [[NSData dataWithBytes:objectAddress length:valueLength] reversed];
    [data getBytes:&value length:data.length];

    return value;
}

@end
