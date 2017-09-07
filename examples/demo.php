<?php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "http://www.baidu.com");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_HEADER, 0);
$output = curl_exec($ch);
curl_close($ch);

class A {
	public function __construct() {}

	public function __destruct() {}
}

for ($i = 0; $i < 5; $i++) { 
	$class = new A();
	$class = null;
}

md5(123456);