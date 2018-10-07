
title: "在Laravel中使用mysql8的时候遇到的错误"
date: 2017-07-31 14:06:00
update: 2017-07-31 14:06:00
author: me
tags:
    - laravel
    - mysql
preview: 使用artisan时候遇到`caching_sha2_password`和`NO_AUTO_CREATE_USER`错误的解决办法。

---

### SQLSTATE[HY000] [2054] The server requested authentication method unknown to the client [`caching_sha2_password`]


```bash
➜  wxapp git:(master) ✗ ./artisan migrate:install

In Connection.php line 664:
                                                                                                         
  SQLSTATE[HY000] [2054] The server requested authentication method unknown to the client (SQL: create table `migrations` (`id` int unsigned not null auto_increment primary key 
  , `migration` varchar(255) not null, `batch` int not null) default character set utf8mb4 collate utf8mb4_unicode_ci)
                            

In Connector.php line 67:
                                                                                           
  SQLSTATE[HY000] [2054] The server requested authentication method unknown to the client 
    
In Connector.php line 67:
                                                                                                         
  PDO::__construct(): The server requested authentication method unknown to the client [caching_sha2_password] 
 
```
> 出错原因：mysql8中已经将默认的密码认证方式改为了`caching_sha2_password`

解决办法：修改mysql8 的密码认证方式，由`caching_sha2_password`变更为`mysql_native_password`
```
create user 'user'@'%' identified by 'password';
ALTER USER 'user'@'%' IDENTIFIED WITH mysql_native_password BY 'password'; 
```

### SQLSTATE[42000]: Syntax error or access violation: 1231 Variable `'sql_mode'` can't be set to the value of `'NO_AUTO_CREATE_USER'`
```bash
➜  wxapp git:(master) ✗ ./artisan migrate:install

In Connection.php line 664:
                                                                                 
  SQLSTATE[42000]: Syntax error or access violation: 1231 Variable 'sql_mode' can't be set to the value of 'NO_AUTO_CREATE_USER' (SQL: create table `migrations` (`id` int unsig 
  ned not null auto_increment primary key, `migration` varchar(255) not null, `batch` int not null) default character set utf8mb4 collate utf8mb4_unicode_ci)
                                   

In MySqlConnector.php line 150:
                                                                                 
  SQLSTATE[42000]: Syntax error or access violation: 1231 Variable 'sql_mode' can't be set to the value of 'NO_AUTO_CREATE_USER' 
   
```
> 出错原因：[Changes in MySQL 8.0.11 (2018-04-19, General Availability)](https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-11.html)
 `NO_AUTO_CREATE_USER`在mysql8中被移除了
 
 解决办法：修改`config/database.php`
由`mysql=>['strict' => true,]`改为 `mysql=>['strict' => false,]`



