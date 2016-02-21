//
//  NHCipherStrength.h
//  NHCerSecurityPro
//
//  Created by hu jiaju on 16/2/19.
//  Copyright © 2016年 hu jiaju. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef struct _cipherUtil {
    int (*score_cipherChar)(const char *cipher);
    NSString *(*password_class)(Class aClass);
    
}NHCipherUtil_t;

#define NHCipherUtil ([NHCipherStrength shareUtil])

@interface NHCipherStrength : NSObject

+ (NHCipherUtil_t *)shareUtil;

@end
