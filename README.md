# NHCerSecurityPro

* * *
#### 文章目录：
<A HREF="#ROP_AR1">AF推荐使用方法</A>
<A HREF="#ROP_AR2">数据层SSL En/Decrypt</A>
<A HREF="#ROP_AR3">AF与nginx双向认证介绍</A>

* * *


#### 正文:

##### [AF推荐使用方法:](#ROP_AR1)
###### *引入AFNetworking
推荐使用Pod导入，方便库管理
```ObjectiveC
pod 'AFNetworking'

```
###### *使用AFNetworking
推荐使用继承自AFHTTPSessionManager创建单例方法
```ObjectiveC
//
//  NHAFEngine.h
//  NHCerSecurityPro
//
//  Created by hu jiaju on 15/7/30.
//  Copyright (c) 2015年 hu jiaju. All rights reserved.
//

#import <AFNetworking/AFNetworking.h>

@interface NHAFEngine : AFHTTPSessionManager

/**
 *	@brief	network engine singleton
 *
 *	@return	instance
 */
+ (NHAFEngine *)share;

```
###### *Cancel Request
3.0之前版本：
```ObjectiveC
/**
 *	@brief	cancel a request
 *
 *	@param 	path 	the request's path
 */
- (void)cancelRequestForpath:(NSString *)path {
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
}
```
3.0之后版本（目前3.x版本弃用了NSURLConnection类等，详见[官方](https://github.com/AFNetworking/AFNetworking)）
```ObjectiveC
/**
 *	@brief	cancel a request
 *
 *	@param 	path 	the request's path
 */
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
}
```
其他用法方法详见例子

##### [数据层SSL En/Decrypt:](#ROP_AR1)
工具包在PROJECT_DIR->同名文件夹->Security,实现加密方法：
```
1.AES加解密
2.RSA加解密
3.RSA签名、验签
4.AES随机秘钥生成
```
##### [AF与nginx双向认证介绍:](#ROP_AR1)
由于我们CA购买时仅支持单向认证，所以不再介绍单向认证，这里以自签名（self－signed）Certificate为例说明（原理不再介绍 网上很多）
###### *准备证书
1.生成CA私钥和自签名证书
->step 1>准备
```
> cd/etc/pki/CA  
> touch serial  
> touchindex.txt  
> echo“00” > serial 
```
->step 2>生成CA私钥
```
> cd/etc/pki/CA/private  
> openssl genrsa -out cakey.pem 2048
```
->step 3>生成CA自签名证书,再生成一个DER格式的证书为iOS做准备
```
> cd/etc/pki/CA  
> openssl req -new –x509 –key private/cakey.pem –out cacert.pem –days 3650  
> openssl x509 -in cacert.pem -outform DER -out ca.cer  
```
2.生成服务器私钥和证书
->step 1>找到一个合适存放私钥的目录文件夹
```
> cd/home/ssl/server 
```
->step 2>生成服务器私钥
```
> openssl genrsa -out server-key.pem 2048 
```
->step 3>生成服务器证书请求
```
> openssl req -new -key server-key.pem -out server-req.csr -days 3650  
```
->step 4>生成服务器证书（由本地CA签发）,再生成一个DER格式的证书为iOS做准备
```
> openssl ca -in server-req.csr -out server-cert.pem -days 3650  
> openssl x509 -in server-cert.pem -outform DER -out server.cer
```
3.生成客户端私钥和证书
->step 1>找到一个合适存放客户端私钥的目录文件夹
```
> cd/home/ssl/client 
```
->step 2>生成客户端私钥
```
> openssl genrsa -out client-key.pem 2048
```
->step 3>生成客户端证书请求
```
> openssl req -new -key client-key.pem -out client-req.csr -days 3650 
```
->step 4>生成客户端证书（由本地CA签发）
```
> openssl ca -in client-req.csr -out client -cert.pem -days 3650  
```
->step 5>将证书转换为DER和p12格式（p12文件用来安全分发客户端证书，一般需要密码保护，此密码会在客户端使用）
```
> openssl x509 -in client-cert.pem -outform DER -out client.cer  
> openssl pkcs12 -export -clcerts -in client-cert.pem -inkey client-key.pem -out client.p12 
```
###### *Nginx相关配置
打开/etc/nginx/nginx.conf，在Server配置中增加以下内容：
```
listen       443;  
ssl on;  
ssl_certificate /home/ssl/server/server-cert.pem;  
ssl_certificate_key /home/ssl/server/server-key.pem;  
ssl_client_certificate /etc/pki/CA/cacert.pem;  
ssl_session_timeout 5m;  
ssl_verify_client  on;  
ssl_protocols TLSv1 TLSv1.1 TLSv1.2; 
ssl_session_cache shared:SSL:10m;
ssl_prefer_server_ciphers on;
```
###### *客户端（iOS）相关配置
1.工程配置及资源
->step 1>info.pist配置（iOS9.x+）
```
因为是自签名证书。所以需要设置ATS（APP Transition Security），相关设置自行解决
```
->step 2>资源配置
```
将在服务器上生成的服务器证书server.cer和客户端P12文件client.p12拷贝到本地，加入到工程的Bundle Resource里
```
->step 3>代码实现
```
代码较长，详见示例
```
###### *Attentions
```
1.设置完ATS后，在设置AFSecurityPolicy时要将ValidatesDomainName属性设置为false，否则验证失败
```
* * *
###### *To Be Continue
```
UIWebView的https请求
```
* * *
###### *Contacter
```
nanhujiaju@gmail.com
```
* * *