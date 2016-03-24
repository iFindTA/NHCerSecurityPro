//
//  NHWebSSLVCR.m
//  NHCerSecurityPro
//
//  Created by hu jiaju on 16/3/22.
//  Copyright © 2016年 hu jiaju. All rights reserved.
//

#import "NHWebSSLVCR.h"
#import <SVProgressHUD.h>

@interface NHWebSSLVCR ()<UIWebViewDelegate,NSURLConnectionDelegate,NSURLConnectionDataDelegate,NSURLSessionDelegate>

@property (nonatomic, strong) UIWebView *webView;
@property (nonatomic, strong) UITextField *tfd;
@property (nonatomic, strong) NSMutableData *htmlData;

@end

@implementation NHWebSSLVCR

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"UIWebView";
    
    self.tabBarItem.title = @"Web";
    
    CGRect bounds = CGRectMake(0, 70, 260, 30);
    _tfd = [[UITextField alloc] initWithFrame:bounds];
    _tfd.borderStyle = UITextBorderStyleBezel;
    _tfd.placeholder = @"input a url that start with 'https'";
    _tfd.text = @"https://am.yewind.com/aa.php";
    [self.view addSubview:_tfd];
    
    bounds = CGRectMake(280, 70, 50, 30);
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = bounds;
    [btn setTitle:@"start" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor blueColor] forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(startRequest) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    
    CGSize size = [UIScreen mainScreen].bounds.size;
    bounds = CGRectMake(0, 130, size.width, size.height-140);
    _webView = [[UIWebView alloc] initWithFrame:bounds];
    _webView.delegate = self;
    _webView.scalesPageToFit = true;
    [self.view addSubview:_webView];
    
}

- (void)startRequest {
    NSString *tmpUrl = [_tfd text];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:tmpUrl]];
    [_webView loadRequest:request];
    
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType {
    
    NSString *tmp = [request.URL absoluteString];
    NSLog(@"request url :%@",tmp);
    if ([request.URL.scheme rangeOfString:@"https"].location != NSNotFound) {
        //开启同步的请求去双向认证
        BOOL use_url_session = true;
        if (!use_url_session) {
            NSURLConnection *conn = [NSURLConnection connectionWithRequest:request delegate:self];
            [conn start];
        }else{
            NSURLSessionConfiguration *conf = [NSURLSessionConfiguration defaultSessionConfiguration];
            //不要使用mainQueue 会堵塞
            //NSOperationQueue *queue = [NSOperationQueue mainQueue];
            NSOperationQueue *queue = [[NSOperationQueue alloc] init];
            queue.name = @"Mutual Author";
            //NSURLSession *session = [NSURLSession sharedSession];
            NSURLSession *session = [NSURLSession sessionWithConfiguration:conf delegate:self delegateQueue:queue];
            NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
                NSString *htmlString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                NSLog(@"load texts:%@",htmlString);
                [_webView loadHTMLString:htmlString baseURL:nil];
            }];
            [task resume];
        }
        
        [webView stopLoading];
        
        return false;
    }
    return YES;
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error {
    [SVProgressHUD showErrorWithStatus:error.localizedDescription];
}

#pragma mark -- NSURLConnection Delegate --

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    
    NSURLCredential * credential;
    assert(challenge != nil);
    credential = nil;
    NSLog(@"----received challenge----");
    // Handle ServerTrust and Client Certificate challenges
    
    NSString *authenticationMethod = [[challenge protectionSpace] authenticationMethod];
    if ([authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        
        NSLog(@"----server verify client----");
        NSString *host = challenge.protectionSpace.host;
        
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        BOOL validDomain = false;
        NSMutableArray *polices = [NSMutableArray array];
        if (validDomain) {
            [polices addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)host)];
        }else{
            [polices addObject:(__bridge_transfer id)SecPolicyCreateBasicX509()];
        }
        SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)polices);
        //pin mode for certificate
        NSString *path = [[NSBundle mainBundle] pathForResource:@"server" ofType:@"cer"];
        NSData *certData = [NSData dataWithContentsOfFile:path];
        NSMutableArray *pinnedCerts = [NSMutableArray arrayWithObjects:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData), nil];
        SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)pinnedCerts);
        
        credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        //completionHandler(NSURLSessionAuthChallengeUseCredential,credential);
        //return;
        
    } else {
        //NSLog(@"self signed trust challange");
       NSLog(@"----client verify server----");
        SecIdentityRef identity = NULL;
        SecTrustRef trust = NULL;
        NSString *p12 = [[NSBundle mainBundle] pathForResource:@"client" ofType:@"p12"];
        NSFileManager *fileManager = [NSFileManager defaultManager];
        if (![fileManager fileExistsAtPath:p12]) {
            NSLog(@"client.p12 file not exist!");
        }else{
            NSData *pkcs12Data = [NSData dataWithContentsOfFile:p12];
            //__strong typeof([NHAFEngine class]) strongSelf = weakSelf;
            if ([NHWebSSLVCR extractIdentity:&identity andTrust:&trust fromPKCS12Data:pkcs12Data]) {
                SecCertificateRef certificate = NULL;
                SecIdentityCopyCertificate(identity, &certificate);
                const void *certs[] = {certificate};
                CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
                credential = [NSURLCredential credentialWithIdentity:identity certificates:(__bridge NSArray *)certArray persistence:NSURLCredentialPersistencePermanent];
            }
        }
    }
    //NSLog(@"credential is %@",credential);
    [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
}

+ (BOOL)extractIdentity:(SecIdentityRef *)outIdentity andTrust:(SecTrustRef *)outTrust fromPKCS12Data:(NSData *)inPKCS12Data {
    
    OSStatus securityErr = errSecSuccess;
    //client certificate password
    NSDictionary *optionsDic = [NSDictionary dictionaryWithObject:@"haha" forKey:(__bridge id)kSecImportExportPassphrase];
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

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    if (_htmlData == nil) {
        _htmlData = [NSMutableData dataWithData:data];
        return;
    }
    [_htmlData appendData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    if (_htmlData) {
        NSString *htmlString = [[NSString alloc] initWithData:_htmlData encoding:NSUTF8StringEncoding];
        NSLog(@"load texts:%@",htmlString);
        [_webView loadHTMLString:htmlString baseURL:nil];
    }
}

#pragma mark -- NSURLSession Delegate --

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    NSString *method = challenge.protectionSpace.authenticationMethod;
    NSLog(@"challenge auth method:%@",method);
    if ([method isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSString *host = challenge.protectionSpace.host;
        NSLog(@"host:%@",host);
        
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        BOOL validDomain = false;
        NSMutableArray *polices = [NSMutableArray array];
        if (validDomain) {
            [polices addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)host)];
        }else{
            [polices addObject:(__bridge_transfer id)SecPolicyCreateBasicX509()];
        }
        SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)polices);
        //pin mode for certificate
        NSString *path = [[NSBundle mainBundle] pathForResource:@"server" ofType:@"cer"];
        NSData *certData = [NSData dataWithContentsOfFile:path];
        NSMutableArray *pinnedCerts = [NSMutableArray arrayWithObjects:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData), nil];
        SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)pinnedCerts);
        
        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential,credential);
        return;
    }
    
    //client authentication
    NSString *thePath = [[NSBundle mainBundle] pathForResource:@"client" ofType:@"p12"];
    NSData *pkcs12Data = [NSData dataWithContentsOfFile:thePath];
    CFDataRef inPKCS12Data = (CFDataRef)CFBridgingRetain(pkcs12Data);
    SecIdentityRef identity;
    
    OSStatus ret = [self extractP12Data:inPKCS12Data toIdentity:&identity];
    if (ret != errSecSuccess) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge,nil);
        return;
    }
    
    SecCertificateRef certificate = NULL;
    SecIdentityCopyCertificate(identity, &certificate);
    const void *certs[] = {certificate};
    CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identity certificates:(NSArray *)CFBridgingRelease(certArray) persistence:NSURLCredentialPersistencePermanent];
    completionHandler(NSURLSessionAuthChallengeUseCredential,credential);
}

- (OSStatus)extractP12Data:(CFDataRef)inP12Data toIdentity:(SecIdentityRef *)identity {
    OSStatus securityErr = errSecSuccess;
    
    CFStringRef pwd = CFSTR("haha");
    const void *keys[] = {kSecImportExportPassphrase};
    const void *values[] = {pwd};
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityErr = SecPKCS12Import(inP12Data, options, &items);
    
    if (securityErr == errSecSuccess) {
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items, 0);
        const void *tmpIdent = NULL;
        tmpIdent = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tmpIdent;
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityErr;
}

@end
