<?php

if (empty($_apm_export)) {
    return false;
}

// fix MongoDB dot (.) in key name
foreach ($_apm_export['profile'] as $key => &$value) {
    if (!empty($value['files'])) {
        foreach ($value['files'] as $k => $v) {
            $new_key = strtr($k, ['.' => '\u002e']);
            if ($new_key != $k) {
                unset($value['files'][$k]);
                $value['files'][$new_key] = $v;
            }
        }
    }

    $new_key = strtr($key, ['.' => '\u002e']);
    if ($new_key != $key) {
        unset($_apm_export['profile'][$key]);
        $_apm_export['profile'][$new_key] = $value;
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
