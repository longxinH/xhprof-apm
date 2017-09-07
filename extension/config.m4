dnl $Id$
dnl config.m4 for extension xhprof_apm

PHP_ARG_ENABLE(xhprof_apm, whether to enable xhprof_apm support,
[  --enable-xhprof_apm           Enable xhprof_apm support])

if test "$PHP_XHPROF_APM" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-xhprof_apm -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/xhprof_apm.h"  # you most likely want to change this
  dnl if test -r $PHP_XHPROF_APM/$SEARCH_FOR; then # path given as parameter
  dnl   XHPROF_APM_DIR=$PHP_XHPROF_APM
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for xhprof_apm files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       XHPROF_APM_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$XHPROF_APM_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the xhprof_apm distribution])
  dnl fi

  dnl # --with-xhprof_apm -> add include path
  dnl PHP_ADD_INCLUDE($XHPROF_APM_DIR/include)

  dnl # --with-xhprof_apm -> check for lib and symbol presence
  dnl LIBNAME=xhprof_apm # you may want to change this
  dnl LIBSYMBOL=xhprof_apm # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $XHPROF_APM_DIR/$PHP_LIBDIR, XHPROF_APM_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_XHPROF_APMLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong xhprof_apm lib version or lib not found])
  dnl ],[
  dnl   -L$XHPROF_APM_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(XHPROF_APM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(xhprof_apm, xhprof_apm.c, $ext_shared)
fi
