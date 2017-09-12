<?php

return [
    'debug' => true,
    'templates' => [
        'cache' => ROOT_DIR . '/cache',
    ],

    // Can be either mongo or mysql.
    'db' => [
        'handler' => 'mongodb'
    ],

    // Mysql configuration
    /*
    'mysql' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'xhprof_apm',
        'charset' => 'utf8',
        'user' => 'root',
        'passwd' => ''
    ],
    */

    // Mongodb configuration
    'mongodb' => [
        'host' => 'mongodb://127.0.0.1:27017',
        'options' => [],
        'db' => 'xhprof_apm',
        'collection' => 'results'
    ],

    'detail' => [
        'count' => 6
    ],
    'date' => [
        'format' => 'Y-m-d H:i:s'
    ],
    'page' => [
        'limit' => 25
    ]
];