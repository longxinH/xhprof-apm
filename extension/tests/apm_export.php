<?php

foreach($_apm_export['profile'] as $func => $metrics) {
    echo str_pad($func, 40) . ":";
    ksort($metrics);
    foreach ($metrics as $name => $value) {

      // Only call counts are stable.
      // Wild card everything else. We still print
      // the metric name to ensure it was collected.
      if ($name != "ct") {
        $value = "*";
      } else {
        $value = str_pad($value, 8, " ", STR_PAD_LEFT);
      }

      echo " {$name}={$value};";
    }
    echo "\n";
}
