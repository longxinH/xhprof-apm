<?php

$container['errorHandler'] = function ($ci) {
    return function ($request, $response, $exception) use ($ci) {
        return $ci->get('view')->render(
            $response->withStatus(500)->withHeader('Content-Type', 'text/html'),
            'error/view.twig',
            [
                'title'     => '发生错误',
                'message'   => $exception->getMessage(),
                'stack_trace' => $exception->getTraceAsString(),
            ]
        );
    };
};