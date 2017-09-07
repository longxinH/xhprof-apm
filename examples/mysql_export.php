<?php
/**
 * mysql table
  CREATE TABLE `xhprof_apm` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `export` text NOT NULL,
    `wt` int(11) NOT NULL,
    `cpu` int(11) NOT NULL,
    `mu` int(11) NOT NULL,
    `date` int(11) NOT NULL,
    `url` text NOT NULL,
    `simple_url` varchar(255) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`)
  ) ENGINE=MyISAM DEFAULT CHARSET=utf8
 */

$dbms = 'mysql';     //数据库类型
$host = '127.0.0.1'; //数据库主机名
$dbName = 'xhprof_apm';    //使用的数据库
$user = '';      //数据库连接用户名
$pass = '';          //对应的密码
$dsn = "$dbms:host=$host;dbname=$dbName";

try {
    $db = new PDO($dsn, $user, $pass); //初始化一个PDO对象
} catch (Exception $e) {
    var_dump($e);
}

$sql = "INSERT INTO xhprof_apm (`export`, `wt`, `cpu`, `mu`, `date`, `url`, `simple_url`) VALUES (?, ?, ?, ?, ?, ?, ?)";
$_sth = $db->prepare($sql);
$_sth->execute(
    [
        json_encode($_apm_export),
        $_apm_export['wt'],
        $_apm_export['cpu'],
        $_apm_export['mu'],
        $_apm_export['meta']['request_date'],
        $_apm_export['meta']['url'],
        $_apm_export['meta']['simple_url']
    ]
);