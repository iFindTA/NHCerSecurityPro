//
//  NHAFEngine.m
//  NHCerSecurityPro
//
//  Created by hu jiaju on 15/7/30.
//  Copyright (c) 2015年 hu jiaju. All rights reserved.
//  nanhujiaju@gmail.com---https://github.com/iFindTA

#import "NHAFEngine.h"
#import "NHSSLCImpPro.h"
#import <Reachability.h>
#import <SVProgressHUD.h>

@interface NHAFEngine ()

@property (nonatomic, strong) Reachability *reachManager;
@property (nonatomic, strong) NSString *token;
@end
static NHAFEngine *instance = nil;
static float requestTimeOut = 60.f;
static NSString *domain  = @"www.baidu.com";
static NSString *logHost = @"https://am.yewind.com";
static NSString *server = @"server";
static NSString *p12file = @"client";
static NSString *p12pwd = @"haha";
@implementation NHAFEngine

+ (NHAFEngine *)share{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (instance == nil) {
            instance = [[[self class] alloc] initWithBaseURL:[NSURL URLWithString:logHost]];
            //set request serializer
            //AFJSONRequestSerializer *request_serial = [AFJSONRequestSerializer serializer];
            AFHTTPRequestSerializer *request_serial = [AFHTTPRequestSerializer serializer];
            request_serial.timeoutInterval = requestTimeOut;
            //[request_serial setValue:@"iphone" forHTTPHeaderField:@"CLIENT"];
            [request_serial setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            //multipart/form-data
            //[request_serial setValue:@"multipart/form-data" forHTTPHeaderField:@"Content-Type"];
            
            instance.requestSerializer = request_serial;
            //set response serializer
            AFJSONResponseSerializer *response_serail = [AFJSONResponseSerializer serializer];
            response_serail.acceptableContentTypes = [response_serail.acceptableContentTypes setByAddingObject:@"text/html"];
            instance.responseSerializer = response_serail;
            
            //客户端认证 需要p12文件
            //*
            [instance setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
                NSLog(@"----received challenge----");
                NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
                __autoreleasing NSURLCredential *__credential = nil;
                if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
                    NSLog(@"----server verify client----");
                    if ([instance.securityPolicy evaluateServerTrust:challenge.protectionSpace.serverTrust forDomain:challenge.protectionSpace.host]) {
                        __credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                        if (__credential) {
                            disposition = NSURLSessionAuthChallengeUseCredential;
                        }else{
                            disposition = NSURLSessionAuthChallengePerformDefaultHandling;
                        }
                    }else{
                        disposition = NSURLSessionAuthChallengeCancelAuthenticationChallenge;
                    }
                }else{
                    //client authentication
                    NSLog(@"----client verify server----");
                    SecIdentityRef identity = NULL;
                    SecTrustRef trust = NULL;
                    NSString *p12 = [[NSBundle mainBundle] pathForResource:p12file ofType:@"p12"];
                    NSFileManager *fileManager = [NSFileManager defaultManager];
                    if (![fileManager fileExistsAtPath:p12]) {
                        NSLog(@"%@.p12 file not exist!",p12file);
                    }else{
                        NSData *pkcs12Data = [NSData dataWithContentsOfFile:p12];
                        //__strong typeof([NHAFEngine class]) strongSelf = weakSelf;
                        if ([NHAFEngine extractIdentity:&identity andTrust:&trust fromPKCS12Data:pkcs12Data]) {
                            SecCertificateRef certificate = NULL;
                            SecIdentityCopyCertificate(identity, &certificate);
                            const void *certs[] = {certificate};
                            CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
                            __credential = [NSURLCredential credentialWithIdentity:identity certificates:(__bridge NSArray *)certArray persistence:NSURLCredentialPersistencePermanent];
                            disposition = NSURLSessionAuthChallengeUseCredential;
                        }
                    }
                }
                *credential = __credential;
                return disposition;
            }];
            //*/
            
            //set security policy
            AFSecurityPolicy *t_policy;
            NSString *cerFilePath = [[NSBundle mainBundle] pathForResource:server ofType:@"cer"];
            NSFileManager *fileManager = [NSFileManager defaultManager];
            if ([fileManager fileExistsAtPath:cerFilePath]) {
                NSData *CAData = [NSData dataWithContentsOfFile:cerFilePath];
                t_policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
                [t_policy setAllowInvalidCertificates:true];
                [t_policy setValidatesDomainName:false];
                [t_policy setPinnedCertificates:[NSSet setWithObjects:CAData, nil]];
                NSLog(@"security policy certificate");
            }else{
                AFSecurityPolicy *t_policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
                [t_policy setAllowInvalidCertificates:true];
                [t_policy setValidatesDomainName:false];
            }
            instance.securityPolicy = t_policy;
        }
    });
    return instance;
}

+(id)allocWithZone:(struct _NSZone *)zone{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (instance == nil) {
            instance = [super allocWithZone:zone];
        }
    });
    return instance;
}

- (id)init {
    self = [super init];
    if (self) {
        _reachManager = [Reachability reachabilityWithHostName:domain];
        [_reachManager startNotifier];
    }
    return self;
}

- (void)cancelAllRequest {
    
    NSArray *dataTasks = self.dataTasks;
    for (NSURLSessionDataTask *task in dataTasks) {
        [task cancel];
    }
//    //老版取消方法
//    NSArray *operations = [[self operationQueue] operations];
//    NSUInteger count = [operations count];
//    if (operations && count) {
//        for (id operator in operations) {
//            NSLog(@"operation class :%@",NSStringFromClass([operator class]));
//            AFHTTPRequestOperation *requestOperation = (AFHTTPRequestOperation *)operator;
//            [requestOperation cancel];
//        }
//    }
}

- (void)cancelRequestForpath:(NSString *)path {
    NSArray *dataTasks = self.dataTasks;
    for (NSURLSessionDataTask *task in dataTasks) {
        NSURLRequest *request = task.originalRequest;
        NSURL *url = [request URL];
        NSString *urlString = [url absoluteString];
        NSString *urlPath = [url path];
        if ([urlPath isEqualToString:path]
            || [urlString rangeOfString:path].location != NSNotFound) {
            [task cancel];
            NSLog(@"request path :%@ canceld!",url.path);
        }
    }
    /*老版取消
    NSArray *operations = [[self operationQueue] operations];
    NSUInteger count = [operations count];
    if (operations && count) {
        for (NSOperation *operator in operations) {
            AFHTTPRequestOperation *requestOperation = (AFHTTPRequestOperation *)operator;
            NSURLRequest *request = [requestOperation request];
            NSURL *url = [request URL];
            NSString *urlString = [url absoluteString];
            NSString *urlPath = [url path];
            if ([urlPath isEqualToString:path]
                || [urlString rangeOfString:path].location != NSNotFound) {
                [requestOperation cancel];
                NSLog(@"request path :%@ canceld!",url.path);
            }
        }
    }
    //*/
}

#pragma mark - Mutual Authentication --

+ (BOOL)extractIdentity:(SecIdentityRef *)outIdentity andTrust:(SecTrustRef *)outTrust fromPKCS12Data:(NSData *)inPKCS12Data {
    
    OSStatus securityErr = errSecSuccess;
    //client certificate password
    NSDictionary *optionsDic = [NSDictionary dictionaryWithObject:p12pwd forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityErr = SecPKCS12Import((__bridge CFDataRef)inPKCS12Data, (__bridge CFDictionaryRef)optionsDic, &items);
    if (securityErr == errSecSuccess) {
        CFDictionaryRef mineIdentAndTrust = CFArrayGetValueAtIndex(items, 0);
        const void *tmpIdentity = NULL;
        tmpIdentity = CFDictionaryGetValue(mineIdentAndTrust, kSecImportItemIdentity);
        *outIdentity = (SecIdentityRef)tmpIdentity;
        const void *tmpTrust = NULL;
        tmpTrust = CFDictionaryGetValue(mineIdentAndTrust, kSecImportItemTrust);
        *outTrust = (SecTrustRef)tmpTrust;
    }else{
        NSLog(@"failed to extract identity/trust with err code :%d",securityErr);
        return false;
    }
    return true;
}

#pragma mark - transfer the encript data with SSL:AESA
-(NSDictionary *)encriptParams:(NSDictionary *)params{
    NSMutableDictionary *t_params = [NSMutableDictionary dictionaryWithDictionary:params];
    if (!t_params || t_params == nil) {
        return t_params;
    }
    NSString *aes_encript_key = NHSSLUtil->aesGenerateKey();
    NSData *params_hex = [NSJSONSerialization dataWithJSONObject:t_params options:NSJSONReadingMutableContainers|NSJSONReadingAllowFragments error:nil];
    NSString *params_str = [[NSString alloc] initWithData:params_hex encoding:NSUTF8StringEncoding];
    NSString *t_cipher_data = NHSSLUtil->aesEncrypt(params_str,aes_encript_key);
    NSString *t_cipher_key = NHSSLUtil->rsaEncrypt(aes_encript_key);
    [t_params setObject:t_cipher_data forKey:@"cipherdata"];
    [t_params setObject:t_cipher_key forKey:@"cipherkey"];
    return t_params;
}

- (BOOL)shouldEncryptForPath:(NSString *)path{
    BOOL should = false;
    if ([path isEqualToString:@"login"]
        ||[path isEqualToString:@"register"]) {
        should = true;
    }
    
    return should;
}

- (NSURLSessionDataTask *)GET:(NSString *)URLString parameters:(id)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure{
    return [super GET:URLString parameters:parameters success:success failure:failure];
}

-(NSURLSessionDataTask *)POST:(NSString *)URLString parameters:(id)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure{
    BOOL shouldEncrypt = false;
    if (shouldEncrypt) {
        parameters = [self encriptParams:parameters];
    }
    NSLog(@"request params:%@",parameters);
    //return [super POST:URLString parameters:parameters success:success failure:failure];
    NSURLSessionDataTask *task = [super POST:URLString parameters:parameters success:^(NSURLSessionDataTask *task, id response){
        int code = [[response objectForKey:@"code"] intValue];
        if (code == 0) {
            if (success) {
                success(task,response);
            }
        }
    } failure:^(NSURLSessionDataTask *task, NSError *err){
        failure(task,err);
    }];
    
    return task;
}

- (BOOL)netEnable {
    if (!_reachManager) {
        _reachManager = [Reachability reachabilityWithHostName:domain];
    }
    return [_reachManager isReachable];
}



- (void)POST:(NSString *)path parameters:(id)parameters vcr:(UIViewController *)vcr success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure{
    ///judge the current network state
    if (![self netEnable]) {
        [SVProgressHUD showErrorWithStatus:@"当前网络不可用！"];
        return;
    }
    if (vcr != nil) {
        vcr.view.userInteractionEnabled = false;
    }
    __weak typeof(&*vcr) weakVCR = vcr;
    [SVProgressHUD showInfoWithStatus:@"请稍候"];
    [super POST:path parameters:parameters success:^(NSURLSessionDataTask *task, id responseObject) {
        if (weakVCR) {
            weakVCR.view.userInteractionEnabled = true;
        }
        [SVProgressHUD dismiss];
        int code = [[responseObject objectForKey:@"code"] intValue];
        if (code == 0) {
            if (success) {
                success(task,responseObject);
            }
        }
        
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        if (weakVCR) {
            weakVCR.view.userInteractionEnabled = true;
        }
        [SVProgressHUD dismiss];
        failure(task,error);
    }];
    
//    [self cancelAllRequest];
}

- (void)POST:(NSString *)path parameters:(id)parameters vcr:(UIViewController *)vcr view:(UIView *)view success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure{
    
    ///judge the current network state
    if (![self netEnable]) {
        [SVProgressHUD showErrorWithStatus:@"当前网络不可用！"];
        return;
    }
    
    if (view != nil) {
        view.userInteractionEnabled = false;
    }
    __weak typeof(&*view) weakView = view;
    [SVProgressHUD showInfoWithStatus:@"请稍候..."];
    [super POST:path parameters:parameters success:^(NSURLSessionDataTask *task, id responseObject) {
        if (weakView) {
            weakView.userInteractionEnabled = true;
        }
        [SVProgressHUD dismiss];
        //[MBProgressHUD hideAllHUDsForView:vcr.view animated:true];
        int code = [[responseObject objectForKey:@"code"] intValue];
        if (code == 0) {
            NSString *token = [responseObject objectForKey:@"token"];
            if (_token) {
                _token = nil;
            }
            _token = [token copy];
            if (success) {
                success(task,responseObject);
            }
        }
        
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        if (weakView) {
            weakView.userInteractionEnabled = true;
        }
        [SVProgressHUD dismiss];
        if (failure) {
            failure(task,error);
        }
    }];
}

@end
