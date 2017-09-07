<?php

$container['view'] = function ($ci) {
    $debug = isset($ci->get('config')['debug']) & $ci->get('config')['debug'];
    $cache_dir = $debug ?
        isset($ci->get('config')['cache']) ? $ci->get('config')['cache'] : ROOT_DIR . '/cache'
        : false;

    $view = new \Slim\Views\Twig(ROOT_DIR . '/templates', [
        'debug' => $debug,
        'cache' => $cache_dir,
        'charset' => 'UTF-8',
    ]);

    $view->addExtension(new \Slim\Views\TwigExtension(
        $ci->get('router'),
        $ci->get('request')->getUri()
    ));

    $view->addExtension(new \Twig\Extension(
        $ci->get('router'),
        $ci->get('request')->getUri()
    ));

    return $view;
};