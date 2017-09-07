<?php
file_put_contents('/tmp/xhprof_apm.log', file_get_contents("php://input") . PHP_EOL, FILE_APPEND);