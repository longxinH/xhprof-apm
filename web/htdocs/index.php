<?php
define('ROOT_DIR', dirname(__DIR__));
define('CONFIG_PATH', ROOT_DIR . '/config/config.php');

require ROOT_DIR . '/vendor/autoload.php';

$app = new \Slim\App();
$container = $app->getContainer();
if (defined('CONFIG_PATH') && file_exists(CONFIG_PATH))
{
    $container['config'] = require CONFIG_PATH;
}
$include = glob(ROOT_DIR . '/include/*.php');

foreach ($include as $file) {
    require $file;
}

$app->run();
