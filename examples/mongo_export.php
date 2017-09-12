<?php
$manager = new MongoDB\Driver\Manager('mongodb://localhost:27017');
$bulk = new \MongoDB\Driver\BulkWrite;
$bulk->insert($_apm_export);
$manager->executeBulkWrite('xhprof_apm.results', $bulk);