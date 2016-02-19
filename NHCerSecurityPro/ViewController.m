//
//  ViewController.m
//  NHCerSecurityPro
//
//  Created by hu jiaju on 15/7/30.
//  Copyright (c) 2015年 hu jiaju. All rights reserved.
//

#import "ViewController.h"
#import "NHAFEngine.h"
#import "SVProgressHUD.h"
#import "NHCipherStrength.h"

#define SV_APP_EXTENSIONS

@interface NHItem : NSObject

@property (nonatomic, copy)NSString *method,*info;

@end

@implementation NHItem

@end

@interface ViewController ()<UITableViewDelegate,UITableViewDataSource>

@property (nonatomic, strong)NSMutableArray *sources;
@property (nonatomic, strong)UITableView *tableView;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    self.title = @"Net Security Pro";
    
    _sources = [[NSMutableArray alloc] initWithCapacity:0];
    NHItem *item = [[NHItem alloc] init];
    item.method = @"GET";
    item.info = @"user/22";
    [_sources addObject:item];
    item = [[NHItem alloc] init];
    item.method = @"POST";
    item.info = @"login";
    [_sources addObject:item];
    item = [[NHItem alloc] init];
    item.method = @"PUT";
    item.info = @"login";
    [_sources addObject:item];
    item = [[NHItem alloc] init];
    item.method = @"Upload";
    item.info = @"index/testupload";
    [_sources addObject:item];
    
    CGRect infoRect = self.view.bounds;
    _tableView = [[UITableView alloc] initWithFrame:infoRect style:UITableViewStylePlain];
    if ([_tableView respondsToSelector:@selector(setSeparatorInset:)]){
        [_tableView setSeparatorInset:UIEdgeInsetsZero];
    }
    _tableView.separatorStyle = UITableViewCellSeparatorStyleNone;
    _tableView.delegate = self;
    _tableView.dataSource = self;
    [self.view addSubview:_tableView];
    /**
     *login info {
     code = 0;
     msg = "";
     time = 1438232849;
     token = "38BF49DC-D6FC-7D2E-61EA-AA2CC0C7B3AF";
     "token_id" = 168;
     }
     */
    
    [SVProgressHUD setDefaultMaskType:SVProgressHUDMaskTypeClear];
}

#pragma mark - tableView data&delegate
-(NSInteger)numberOfSectionsInTableView:(UITableView *)tableView{
    return 1;
}

-(NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section{
    return _sources.count;
}

-(CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath{
    return 50.f;
}

-(UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath{
    static NSString *cellIdentifier = @"cellIdentifier";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellIdentifier];
    if(cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellIdentifier];
    }
    cell.selectionStyle = UITableViewCellSelectionStyleGray;
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    UIView *destView = cell.contentView;
    [destView.subviews makeObjectsPerformSelector:@selector(removeFromSuperview)];
    [destView.layer.sublayers makeObjectsPerformSelector:@selector(removeFromSuperlayer)];
    
    NSInteger row = [indexPath row];
    
    NHItem *item = [_sources objectAtIndex:row];
    CGRect infoRect = CGRectMake(0, 0, 320, 50.f);
    UILabel *infoLabel = [[UILabel alloc] initWithFrame:infoRect];
    infoLabel.font = [UIFont systemFontOfSize:18];
    infoLabel.text = [NSString stringWithFormat:@"METHOD:%@---Info:%@",item.method,item.info];
    [destView addSubview:infoLabel];
    
    return cell;

}

-(void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath{
    [tableView deselectRowAtIndexPath:indexPath animated:true];
    
    UITableViewCell *cell = [tableView cellForRowAtIndexPath:indexPath];
    //[SVProgressHUD showWithStatus:@"请稍后..."];
    NHItem *item = [_sources objectAtIndex:indexPath.row];
    NSMutableDictionary *params = [NSMutableDictionary dictionary];
    [params setObject:@"15958199883" forKey:@"phone"];
    [params setObject:@"123456" forKey:@"pwd"];
    NSString *password ;
    if ([item.method isEqualToString:@"GET"]) {
        [[NHAFEngine share] GET:item.info parameters:params success:^(NSURLSessionDataTask *task, id responseObject) {
            NSLog(@"responseObject:%@",responseObject);
            NSString *ret = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:responseObject options:NSJSONReadingMutableLeaves|NSJSONWritingPrettyPrinted error:nil] encoding:NSUTF8StringEncoding];
            [SVProgressHUD showSuccessWithStatus:ret];
        } failure:^(NSURLSessionDataTask *task, NSError *error) {
            NSLog(@"error occured:%@",error.localizedDescription);
            [SVProgressHUD dismiss];
        }];
        
        password = @"123456";
        
    }else if ([item.method isEqualToString:@"POST"]){
        [[NHAFEngine share] POST:item.info parameters:params success:^(NSURLSessionDataTask *task, id responseObject) {
            NSString *ret = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:responseObject options:NSJSONReadingMutableLeaves|NSJSONWritingPrettyPrinted error:nil] encoding:NSUTF8StringEncoding];
            [SVProgressHUD showSuccessWithStatus:ret];
        } failure:^(NSURLSessionDataTask *task, NSError *error) {
            NSLog(@"error occured:%@",error.localizedDescription);
            [SVProgressHUD showErrorWithStatus:error.localizedDescription];
        }];
        
        password = @"410752";
    }else if ([item.method isEqualToString:@"PUT"]){
        NSLog(@"start request !");
//        [[NHAFEngine share] POST:item.info parameters:params vcr:self success:^(NSURLSessionDataTask *task, id responseObj) {
//            NSString *ret = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:responseObj options:NSJSONReadingMutableLeaves|NSJSONWritingPrettyPrinted error:nil] encoding:NSUTF8StringEncoding];
//            [SVProgressHUD showSuccessWithStatus:ret];
//             NSLog(@"ret:%@",ret);
//        } failure:^(NSURLSessionDataTask *task, NSError *error) {
//            NSLog(@"error occured:%@",error.localizedDescription);
//            //[SVProgressHUD showErrorWithStatus:error.localizedDescription];
//        }];
        [[NHAFEngine share] POST:item.info parameters:params vcr:self view:nil success:^(NSURLSessionDataTask *task, id responseObj) {
            NSString *ret = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:responseObj options:NSJSONReadingMutableLeaves|NSJSONWritingPrettyPrinted error:nil] encoding:NSUTF8StringEncoding];
            //[SVProgressHUD showSuccessWithStatus:ret];
            
            NSLog(@"ret:%@",ret);
        } failure:^(NSURLSessionDataTask *task, NSError *error) {
            NSLog(@"error occured:%@",error.localizedDescription);
            //[SVProgressHUD showErrorWithStatus:error.localizedDescription];
        }];
        
        password = @"62562wiu];/.,HJAu";
    }else if ([item.method isEqualToString:@"Upload"]){
        NSString *filePath = [[NSBundle mainBundle] pathForResource:@"t_default_icon@2x" ofType:@"png"];
        UIImage *image = [UIImage imageWithContentsOfFile:filePath];
        NSData *binaryData = UIImagePNGRepresentation(image);
        [[NHAFEngine share] POST:item.info parameters:params constructingBodyWithBlock:^(id<AFMultipartFormData> formData) {
            [formData appendPartWithFileData:binaryData name:@"test" fileName:@"image.png" mimeType:@"image/png"];
        } success:^(NSURLSessionDataTask *task, id responseObject) {
            [SVProgressHUD showSuccessWithStatus:@"successfully!"];
        } failure:^(NSURLSessionDataTask *task, NSError *error) {
            NSLog(@"error occured:%@",error.localizedDescription);
            [SVProgressHUD showErrorWithStatus:error.localizedDescription];
        }];
        
        password = @"410626nanhujiaju";
    }
    
    int score = NHCipherUtil->score_cipherChar([password UTF8String]);
    NSLog(@"score:%zd",score);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
