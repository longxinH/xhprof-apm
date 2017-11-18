<?php

if (empty($_apm_export)) {
    return false;
}

// 新版的mongokey中不能包含`.`
foreach($_apm_export['profile'] as $key => &$value) {
    if (!empty($value['files'])){
        foreach ($value['files'] as $k => $v){
            $nk = strtr($k, ['.'=> '_']);
            if ($nk != $k){
                unset($value['files'][$k]);
                $value['files'][$nk] = $v;
            }
        }
    }

    $nkey = strtr($key, ['.' => '_']);
    if ($nkey != $key){
        unset($_apm_export['profile'][$key]);
        $_apm_export['profile'][$nkey] = $value;
    }
}

try {
    $manager = new MongoDB\Driver\Manager('mongodb://localhost:27017');
    $bulk    = new \MongoDB\Driver\BulkWrite;
    $bulk->insert($_apm_export);
    $result = $manager->executeBulkWrite('xhprof_apm.results', $bulk);
} catch (Exception $e) {
    var_dump($e->getMessage());
    exit;
}
