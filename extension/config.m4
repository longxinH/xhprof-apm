PHP_ARG_ENABLE(xhprof_apm, whether to enable xhprof_apm support,
[  --enable-xhprof_apm           Enable xhprof_apm support])

if test "$PHP_XHPROF_APM" != "no"; then

  AC_MSG_CHECKING([PHP version])

  tmp_version=$PHP_VERSION
  if test -z "$tmp_version"; then
    if test -z "$PHP_CONFIG"; then
      AC_MSG_ERROR([php-config not found])
    fi
    php_version=`$PHP_CONFIG --version 2>/dev/null|head -n 1|sed -e 's#\([0-9]\.[0-9]*\.[0-9]*\)\(.*\)#\1#'`
  else
    php_version=`echo "$tmp_version"|sed -e 's#\([0-9]\.[0-9]*\.[0-9]*\)\(.*\)#\1#'`
  fi

  if test -z "$php_version"; then
    AC_MSG_ERROR([failed to detect PHP version, please report])
  fi

  ac_IFS=$IFS
  IFS="."
  set $php_version
  IFS=$ac_IFS
  apm_php_version=`expr [$]1 \* 1000000 + [$]2 \* 1000 + [$]3`

  if test "$apm_php_version" -le "5003000"; then
    AC_MSG_ERROR([You need at least PHP 5.3.0 to be able to use this version of Xhprof-apm. PHP $php_version found])
  else
    AC_MSG_RESULT([$php_version, ok])
  fi

  PHP_NEW_EXTENSION(xhprof_apm, xhprof_apm.c, $ext_shared)
fi
