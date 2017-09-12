<?php

$container['db'] = function ($ci) {
    $config = $ci->get('config');
    $handler = isset($config['db']['handler']) ? strtolower($config['db']['handler']) : null;

    switch ($handler) {
        case 'mongodb' :
            $options = !empty($config['mongodb']['options']) ? $config['mongodb']['options'] : [];
            $host = isset($config['mongodb']['host']) ? $config['mongodb']['host'] : null;
            $db = isset($config['mongodb']['db']) ? $config['mongodb']['db'] : 'xhprof_apm';
            $collection = isset($config['mongodb']['collection']) ? $config['mongodb']['collection'] : 'results';
            return new \Database\Mongo($host, $options, $db, $collection);
        case 'mysql' :
        default:
            $host = isset($config['mysql']['host']) ? $config['mysql']['host'] : null;
            $name = isset($config['mysql']['name']) ? $config['mysql']['name'] : null;
            $charset = isset($config['mysql']['charset']) ? $config['mysql']['charset'] : null;
            $usr = isset($config['mysql']['user']) ? $config['mysql']['user'] : null;
            $pwd = isset($config['mysql']['passwd']) ? $config['mysql']['passwd'] : null;
            return new \Database\Mysql($host, $usr, $pwd, $name, $charset);
    }
};