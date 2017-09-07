<?php

return [
    'debug' => true,
    'templates' => [
        'cache' => ROOT_DIR . '/cache',
    ],
    'db' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'xhprof_apm',
        'charset' => 'utf8',
        'user' => 'root',
        'passwd' => ''
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