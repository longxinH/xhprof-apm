<?php

$container['db'] = function ($ci) {
    $host = isset($ci->get('config')['db']['host']) ? $ci->get('config')['db']['host'] : null;
    $name = isset($ci->get('config')['db']['name']) ? $ci->get('config')['db']['name'] : null;
    $charset = isset($ci->get('config')['db']['charset']) ? $ci->get('config')['db']['charset'] : null;
    $usr = isset($ci->get('config')['db']['user']) ? $ci->get('config')['db']['user'] : null;
    $pwd = isset($ci->get('config')['db']['passwd']) ? $ci->get('config')['db']['passwd'] : null;

    return new \Database\Mysql($host, $usr, $pwd, $name, $charset);
};