dnl ######################################################
dnl Check for libfabric
dnl ######################################################
AC_DEFUN([NG_WITH_LIBFABRIC], [
  AC_ARG_WITH([libfabric],
    [AS_HELP_STRING([--with-libfabric@<:@=PATH@:>@], [Specify the path to libfabric.pc or directory containing libfabric.pc (default: auto, disabled if not found)])],
    [with_libfabric_path=$withval],
    [with_libfabric_path=auto]
  )

  enable_libfabric=no
  AS_IF([test "x$with_libfabric_path" != "xno"], [
    AC_MSG_CHECKING([for libfabric])
    PKG_PROG_PKG_CONFIG
    AS_IF([test "x$PKG_CONFIG" = "x"], [
      AC_MSG_RESULT([not found (pkg-config not found)])
      AS_IF([test "x$with_libfabric_path" != "xauto"], [
        AC_MSG_ERROR([pkg-config not found, required if --with-libfabric is specified])
      ], [
        AC_MSG_WARN([pkg-config not found, libfabric module will be disabled])
      ])
    ], [
      ORIG_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AS_IF([test "x$with_libfabric_path" != "xyes" && test "x$with_libfabric_path" != "xauto"], [
          PKG_CONFIG_PATH="$with_libfabric_path:$PKG_CONFIG_PATH"
          # if path is a directory, append /pkgconfig
          AS_IF([test -d "$with_libfabric_path/pkgconfig"], [
              PKG_CONFIG_PATH="$with_libfabric_path/pkgconfig:$ORIG_PKG_CONFIG_PATH"
          ])
      ])
      PKG_CHECK_MODULES([LIBFABRIC], [libfabric >= 1.0], [
        AC_MSG_RESULT([yes])
        enable_libfabric=yes
        LIBS="$LIBS $LIBFABRIC_LIBS"
        CFLAGS="$CFLAGS $LIBFABRIC_CFLAGS"
      ], [
        AC_MSG_RESULT([no])
        AS_IF([test "x$with_libfabric_path" != "xauto"], [
           AC_MSG_ERROR([libfabric not found or version too old, but was explicitly requested with --with-libfabric=$with_libfabric_path])
        ], [
           AC_MSG_WARN([libfabric not found or version too old. Will not build libfabric module.])
        ])
      ])
      PKG_CONFIG_PATH="$ORIG_PKG_CONFIG_PATH"
    ])
  ])
])
