xhprof-apm
====== 
[PHP7版本](https://github.com/longxinH/xhprof-apm/tree/php7)

xhprof-apm 是一款非侵入式监控平台，基于[xhprof](https://github.com/phacility/xhprof)和[xhgui](https://github.com/perftools/xhgui)。可以方便的查看PHP执行过程，调用次数，CPU和内存使用情况。部署简单方便，不需要修改线上代码，即可开启性能分析。

部署在开发环境可以方便调试，部署在线上服务器可以快速定位线上性能问题。

对每次请求都执行性能分析会造成服务性能有轻微的影响。但服务器CPU和内存的消耗是不可忽略的。为了减少对内存和CPU的消耗，可以通过配置控制性能分析的频率。

![list](https://github.com/longxinH/xhprof-apm/blob/master/docs/imgs/list.jpeg)

![symbol_1](https://github.com/longxinH/xhprof-apm/blob/master/docs/imgs/symbol_1.jpeg)

![symbol_2](https://github.com/longxinH/xhprof-apm/blob/master/docs/imgs/symbol_2.jpeg)

### 配置要求
 * PHP 5.3 - PHP 5.6
 * MongoDB 3.0.0 +
 * MongoDB Extension 1.2.6 +
 * 不支持CLI模式
 * 与xhprof冲突
 
## 模块

xhprof-apm 主要由两个部分组成：

 * 日志管理界面（https://github.com/longxinH/xhprof-apm/tree/master/web)
 * PHP扩展（https://github.com/longxinH/xhprof-apm/tree/master/extension)

 ### 日志管理界面
 基于[xhgui](https://github.com/perftools/xhgui)，slim升级到3.0，对界面进行汉化和代码调整。
 
 ### PHP扩展
 基于[xhprof](https://github.com/phacility/xhprof)，修复部分BUG，增加PDO预处理占位符在日志中转换为实际参数，CURL地址记录。在RINIT（Request Initialization）时候，开启日志记录，RSHUTDOWN（Request Shutdown）时候，进行性能分析提交。
 
## 使用

### 下载
```
git clone https://github.com/longxinH/xhprof-apm.git
```

### 扩展安装
```
cd xhprof-apm/extension/
/path/to/php5/bin/phpize
./configure --with-php-config=/path/to/php5/bin/php-config
make && sudo make install
```

### php.ini
```
[xhprof_apm]
extension = xhprof_apm.so
xhprof_apm.config_ini = ini/apm.ini
xhprof_apm.export = php
xhprof_apm.php_file = /path/to/xhprof-apm/export.php
```

### php.ini配置说明
|      配置选项        |      选项      |   说明    |
| --------------- |:-------------:|:---------|
|xhprof_apm.config_ini  | 配置文件的路径(支持绝对或相对路径) | 用于控制扩展开关和选项，使用相对路径可独立控制项目|
|xhprof_apm.export  | 可选php、curl | 日志提交方式|
|xhprof_apm.php_file  | 脚本路径 | export = php时，在请求结束后，会将结果注册到$_apm_export变量，在此脚本中获取到日志结果，用户自行后续操作|
|xhprof_apm.curl_uri  | http地址 | export = curl时，在请求结束后，会将结果提交到该地址|
|xhprof_apm.curl_timeout_ms  | 毫秒级 (1s = 1000ms) | curl超时，默认值：1000ms|

### php_file
```php
<?php
var_dump($_apm_export);
```

### curl_uri
curl的数据经过json_encode处理
```php
<?php
file_put_contents('/tmp/xhprof_apm.log', file_get_contents("php://input") . PHP_EOL, FILE_APPEND);
```

### 预定义常量
```php
APM_FLAGS_NO_BUILTINS (int) 使得跳过所有内置（内部）函数
APM_FLAGS_CPU (int) 使输出的性能数据中添加 CPU 数据
APM_FLAGS_MEMORY (int) 使输出的性能数据中添加内存数据
APM_FLAGS_FILES (int) 记录文件调用栈
```

### 数据格式
```php
array {
  ["meta"] =>
      array {
        ["url"] => 完整请求地址 (string)
        ["simple_url"] => 精简后的地址，保留请求参数，但不保留值，用作特定参数请求的匹配 (string)
        ["request_date"] => 请求时间戳 (int)
        ["SERVER"] => $_SERVER的值 (array)
        ["GET"] => $_GET的值 (array)
      }
  ["profile"] => 性能分析 (array)
  ["wt"] => 执行时间 (int)
  ["cpu"] => CPU执行时间 (int)
  ["mu"] => 内存使用 (int)
  ["debug"] => 是否debug模式启动 (int)
}
```
### 性能分析数据格式
需要在apm.ini配置 `APM_FLAGS_FILES` 才能记录 `files` 栈
```php
array {
    [函数名]=>
      array {
        ["ct"] => 调用次数 (int)
        ["wt"] => 函数方法执行的时间耗时 (int)
        ["cpu"] => 函数方法执行消耗的cpu时间 (int)
        ["mu"] => 函数方法所使用的内存 (int)
        ["pmu"] => 函数方法所使用的内存峰值 (int)
        ["files"] => array {
          [文件名] =>
            array {
              [行号] => 调用次数 (int)
            }
        }
    }
}
```

#### [更多例子](https://github.com/longxinH/xhprof-apm/blob/master/examples/)

### config_ini配置说明
可采用相对路径的形式，单独对项目控制。

|      配置选项        |      选项      |   说明    |
| --------------- |:-------------:|:---------|
|apm.auto  | 1、0 | 1：开启、0：关闭|
|apm.flags  | APM_FLAGS_NO_BUILTINS、APM_FLAGS_CPU、APM_FLAGS_MEMORY、APM_FLAGS_FILES | 预定义变量|
|apm.ignored  | array的可选选项 |忽略性能分析中的某些函数 |
|apm.rate  | 0 - 100 |频率设置，按照0到100的百分比，如果auto设为0，此选项不会生效，如设置大于100会每次开启，等于0则不开启。当不需要此选项时，请注释掉|
|apm.debug  | GET参数名 |此选项可通过特定的GET参数开启性能分析，注释即可关闭。如设置auto = 0，同时GET参数中带有设置值 (例如 http://localhost/?apm_debug) ，也会开启性能分析，优先级高于auto。|

```
apm.auto = 1

;APM_FLAGS_NO_BUILTINS
;APM_FLAGS_CPU
;APM_FLAGS_MEMORY
;APM_FLAGS_FILES
apm.flags = APM_FLAGS_CPU | APM_FLAGS_MEMORY

apm.ignored[] = md5

;0 - 100
;apm.rate = 30

apm.debug = apm_debug
```

## 日志管理界面
```
cd xhprof-apm/web/
composer install
```

### 存储方式
推荐使用MongoDB
 * [MongoDB](https://github.com/longxinH/xhprof-apm/blob/master/README_CN.md#mongodb)

### MongoDB
1. 安装MongoDB [官网](https://www.mongodb.com/)
2. MongoDB扩展 [mongo-php-driver](https://github.com/mongodb/mongo-php-driver)
3. 启动MongoDB
3. 创建索引
```
$ mongo
> use xhprof_apm
> db.results.createIndex({'wt' : -1})
> db.results.createIndex({'cpu' : -1})
> db.results.createIndex({'mu' : -1})
```

### Nginx
```
server {
    listen   80;
    server_name apm.com;

    root   /path/to/xhprof-apm/web/htdocs;
    index  index.php;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        fastcgi_pass    127.0.0.1:9000;
        fastcgi_index   index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;  
    }
}
```
