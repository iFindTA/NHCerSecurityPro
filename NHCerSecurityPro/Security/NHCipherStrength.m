//
//  NHCipherStrength.m
//  NHCerSecurityPro
//
//  Created by hu jiaju on 16/2/19.
//  Copyright © 2016年 hu jiaju. All rights reserved.
//  nanhujiaju@gmail.com---https://github.com/iFindTA

#import "NHCipherStrength.h"
#import <objc/runtime.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <ctype.h>
#include <stdlib.h>

static NHCipherUtil_t *util = nil;
static NHCipherStrength *instance = nil;

@interface NHCipherStrength ()

- (int)score_passphrase:(const char *)passphrase;
- (NSString *)password_class:(Class)aClass;

@end

static int _score_passphrase(const char *passphrase) {
    return [instance score_passphrase:passphrase];
}

static NSString *_password_class(Class aClass) {
    return [instance password_class:aClass];
}

@implementation NHCipherStrength

+ (NHCipherUtil_t *)shareUtil {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        if (instance == nil) {
            instance = [[[self class] alloc] init];
        }
        
        util = malloc(sizeof(NHCipherUtil_t));
        util->score_cipherChar = _score_passphrase;
        util->password_class = _password_class;
    });
    return util;
}

int key_distance(char a, char b) {
    const char *qwerty_lc = "`1234567890-="
    "qwertyuiop[]\\"
    " asdfghjkl;' "
    "  zxcvbnm,./ ";
    const char *qwerty_uc = "~!@#$%^&*()_+"
    "QWERTYUIOP{}|"
    " ASDFGHJKL:\" "
    "  ZXCVBNM<>? ";
    int pos_a,pos_b,dist;
    
    if (strchr(qwerty_lc, a)) {
        pos_a = strchr(qwerty_lc, a) - qwerty_lc;
    }else if (strchr(qwerty_uc, a)){
        pos_a = strchr(qwerty_uc, a) - qwerty_uc;
    }else {
        return -2;
    }
    
    if (strchr(qwerty_lc, b)) {
        pos_b = strchr(qwerty_lc, b) - qwerty_lc;
    }else if (strchr(qwerty_uc, b)) {
        pos_b = strchr(qwerty_uc, b) - qwerty_uc;
    }else {
        return -1;
    }
    //行距离+列距离
    dist = abs((pos_a/13) - (pos_b/13))
    + abs((pos_a%13 - pos_a%13));
    return dist;
}

- (int)score_passphrase:(const char *)passphrase {
    int total_score = 0;
    int unit_score ;
    int distances[strlen(passphrase)];
    int i;
    
    //cipher length
    unit_score = strlen(passphrase) / 4;
    total_score += MIN(3, unit_score);
    
    // upword
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (isupper(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // low charactor
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (islower(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // number
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (isdigit(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // special charactor
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (!isalnum(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // key distance
    distances[0] = 0;
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (passphrase[i+1]) {
            int dist = key_distance(passphrase[i], passphrase[i+1]);
            if (dist > 1) {
                int j, exists = 0;
                for (j = 0; distances[j]; ++j) {
                    if (distances[j] == dist) {
                        exists = 1;
                    }
                }
                if (!exists) {
                    distances[j] = dist;
                    distances[j+1] = 0;
                    unit_score++;
                }
            }
        }
    }
    total_score += MIN(3, unit_score);
    
    return ((total_score/18.0f) * 100);
}

- (NSString *)password_class:(Class)aClass {
    
    if (aClass != nil) {
        unsigned int count;
        NSMutableString *selectors = [NSMutableString string];
        Method *methods = class_copyMethodList(aClass, &count);
        for (int i = 0; i < count; i++) {
            Method method = methods[i];
            SEL selector = method_getName(method);
            NSString *tmpSel_name = NSStringFromSelector(selector);
            NSLog(@"method name :%@",NSStringFromSelector(selector));
            [selectors appendString:tmpSel_name];
        }
        
        return [selectors copy];
    }
    return NSStringFromClass([self class]);
}

@end
