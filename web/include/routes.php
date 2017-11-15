<?php

$app->get('/', 'Controller\Run:index')->setName('home');
$app->get('/run/view', 'Controller\Run:view')->setName('run.view');
$app->get('/run/url', 'Controller\Run:url')->setName('run.url');
$app->get('/run/symbol', 'Controller\Run:symbol')->setName('run.symbol');
$app->get('/run/callgraph', 'Controller\Run:callgraph')->setName('run.callgraph');
$app->get('/run/callgraph/data', 'Controller\Run:callgraphData')->setName('run.callgraph.data');
$app->get('/run/symbol/short', 'Controller\Run:symbolShort')->setName('run.symbol-short');
$app->get('/run/flamegraph', 'Controller\Run:flamegraph')->setName('run.flamegraph');
$app->get('/run/flamegraph/data', 'Controller\Run:flamegraphData')->setName('run.flamegraph.data');
$app->get('/run/compare', 'Controller\Run:compare')->setName('run.compare');
$app->get('/url/view', 'Controller\Run:url')->setName('url.view');
$app->get('/url/stack', 'Controller\Run:stack')->setName('url.stack');