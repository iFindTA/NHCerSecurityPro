//
//  NHWebSSLVCR.m
//  NHCerSecurityPro
//
//  Created by hu jiaju on 16/3/22.
//  Copyright © 2016年 hu jiaju. All rights reserved.
//

#import "NHWebSSLVCR.h"
#import <SVProgressHUD.h>

@interface NHWebSSLVCR ()<UIWebViewDelegate>

@property (nonatomic, strong) UIWebView *webView;
@property (nonatomic, strong) UITextField *tfd;

@end

@implementation NHWebSSLVCR

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"UIWebView";
    
    self.tabBarItem.title = @"Web";
    
    CGRect bounds = CGRectMake(0, 70, 200, 30);
    _tfd = [[UITextField alloc] initWithFrame:bounds];
    _tfd.borderStyle = UITextBorderStyleBezel;
    _tfd.placeholder = @"input a url that start with 'https'";
    _tfd.text = @"https://am.yewind.com/aa.php";
    [self.view addSubview:_tfd];
    
    bounds = CGRectMake(220, 70, 50, 30);
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
    NSString *url=[[request URL]absoluteString];
    
    return YES;
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error {
    [SVProgressHUD showErrorWithStatus:error.localizedDescription];
}

@end
