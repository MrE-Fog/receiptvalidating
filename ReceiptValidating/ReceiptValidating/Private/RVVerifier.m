//
//  RVVerifier.m
//  ReceiptValidating
//
//  Created by Pawel Klapuch on 11/25/20.
//

#import "RVVerifier.h"
#import "NSData+Hex.h"

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

@implementation RVVerifier

+ (nullable NSData *)readContentsOfReceipt:(NSData *)receipt rootCertificate:(NSData *)rootCertificate error:(NSError **)error {
    
    NSData *contentsData = nil;
    int status = 1;
    
    BIO *p7_bio = NULL;
    BIO *x509_bio = NULL;
    BIO *verification_bio = NULL;
    
    PKCS7 *p7 = NULL;
    X509 *x509 = NULL;
    X509_STORE *store = NULL;
    
    p7_bio = BIO_new_mem_buf(receipt.bytes, (int)receipt.length);
    status = p7_bio != NULL ? 1 : 0;
    
    if (status == 1) {
        status = d2i_PKCS7_bio(p7_bio, &p7) != NULL ? 1 : 0;
    }
    
    if (status == 1) {
        x509_bio = BIO_new_mem_buf(rootCertificate.bytes, (int)rootCertificate.length);
        status = x509_bio != NULL ? 1 : 0;
    }
    
    if (status == 1) {
        x509 = PEM_read_bio_X509(x509_bio, NULL, 0, NULL);
        status = x509 != NULL ? 1 : 0;
    }
    
    if (status == 1) {
        store = X509_STORE_new();
        status = store != NULL ? 1 : 0;
    }
    
    if (status == 1) {
        status = X509_STORE_add_cert(store, x509);
    }
    
    if (status == 1) {
        verification_bio = BIO_new(BIO_s_mem());
        status = verification_bio != NULL ? 1 : 0;
    }
    
    if (status == 1) {
        status = PKCS7_verify(p7, NULL, store, NULL, verification_bio, 0);
    }
    
    if (status == 1) {
        
        struct pkcs7_st *contents = p7->d.sign->contents;
        if (PKCS7_type_is_data(contents))
        {
            ASN1_OCTET_STRING *octets = contents->d.data;
            contentsData = [NSData dataWithBytes:octets->data length:octets->length];
        }
    }
    
    if (verification_bio != NULL) { BIO_free(verification_bio); }
    if (store != NULL) { X509_STORE_free(store); }
    if (x509 != NULL) { X509_free(x509); }
    if (p7_bio != NULL) { BIO_free(p7_bio); }
    if (p7 != NULL) { PKCS7_free(p7); }
    
    return contentsData;
}

+ (BOOL)verifyHashWithVendorId:(NSData *)vendorId
               receiptOpaqueId:(NSData *)receiptOpaqueId
           receiptBundleIdData:(NSData *)receiptBundleIdData
                   receiptHash:(NSData *)receiptHash {
    
    //NSLog(@"vendorId: %@", vendorId.toHexString);
    //NSLog(@"receipt opaque: %@", receiptOpaqueId.toHexString);
    //NSLog(@"receipt bundleId: %@", receiptBundleIdData.toHexString);
    //NSLog(@"receipt hash: %@", receiptHash.toHexString);
    
    NSMutableData *input = [NSMutableData new];
    [input appendData:vendorId];
    [input appendData:receiptOpaqueId];
    [input appendData:receiptBundleIdData];
    //NSLog(@"input: %@", input.toHexString);
    
    NSData *sha1 = [self sha1:input];
    //NSLog(@"sha1: %@", sha1.toHexString);
    
    return [sha1 isEqualToData:receiptHash];
}

+ (nullable NSData *)sha1:(NSData *)data {
    
    NSData *outputData = nil;
    int status = 1;
        
    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA_CTX ctxSha;
    status = SHA1_Init(&ctxSha);
    
    if (status == 1) {
        status = SHA1_Update(&ctxSha, data.bytes, data.length);
    }
    
    if (status == 1) {
        status = SHA1_Final(hash, &ctxSha);
    }
        
    if (status == 1) {
        
        outputData = [NSData dataWithBytes:hash length:SHA_DIGEST_LENGTH];
    }
    
    return outputData;
}

@end
