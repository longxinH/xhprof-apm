--TEST--
Basic Profiling Test
--INI--
xhprof_apm.config_ini = ./tests/apm.ini
xhprof_apm.php_file = ./tests/apm_export.php
--FILE--
<?php
function bar() {
  return 1;
}

function foo($x) {
  $sum = 0;
  for ($idx = 0; $idx < 2; $idx++) {
     $sum += bar();
  }
  return strlen("hello: {$x}");
}

foo("this is a test");
?>
--EXPECT--
main()==>load::tests/002.php            : cpu=*; ct=       1; mu=*; pmu=*; wt=*;
foo==>bar                               : cpu=*; ct=       2; mu=*; pmu=*; wt=*;
main()==>foo                            : cpu=*; ct=       1; mu=*; pmu=*; wt=*;
main()                                  : cpu=*; ct=       1; mu=*; pmu=*; wt=*;