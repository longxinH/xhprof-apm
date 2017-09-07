<?php

class Util
{

    public static function formatTime($value)
    {
        $val = round($value / 1000,3);
        if ($val == 0) {
            $val = round($value / 1000);
        }

        return $val;
    }

    public static function formatBytes($value)
    {
        $val = round($value / 1048576,1);
        if ($val==0) {
            $val = round($value / 1048576);
        }

        return $val;
    }

}
