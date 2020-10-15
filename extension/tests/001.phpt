--TEST--
Check for xhprof_apm presence
--SKIPIF--
<?php if (!extension_loaded("xhprof_apm")) print "skip"; ?>
--FILE--
<?php 
echo "xhprof_apm extension is available";
?>
--EXPECT--
xhprof_apm extension is available
