<?php

$container['profiles'] = function ($ci) {
    return new \Profiles($ci->get('db'));
};