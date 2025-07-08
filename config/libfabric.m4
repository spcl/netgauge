dnl ######################################################
dnl Check for libfabric
dnl ######################################################
AC_DEFUN([NG_WITH_LIBFABRIC], [
  dnl Parse --with-libfabric argument (accepts path or auto)
  AC_ARG_WITH([libfabric],
    [AS_HELP_STRING([--with-libfabric@<:@=PATH@:>@], [Specify the path to libfabric.pc or directory containing libfabric.pc (default: auto, disabled if not found)])],
    [with_libfabric_path=$withval],
    [with_libfabric_path=auto]
  )

  enable_libfabric=no
  dnl Only proceed if user did not explicitly disable libfabric
  AS_IF([test "x$with_libfabric_path" != "xno"], [
    AC_MSG_CHECKING([for libfabric])
    dnl Find pkg-config tool
    PKG_PROG_PKG_CONFIG
    AS_IF([test "x$PKG_CONFIG" = "x"], [
      dnl pkg-config not found
      AC_MSG_RESULT([not found (pkg-config not found)])
      AS_IF([test "x$with_libfabric_path" != "xauto"], [
        dnl User explicitly requested libfabric, error out
        AC_MSG_ERROR([pkg-config not found, required if --with-libfabric is specified])
      ], [
        dnl Otherwise, just warn and disable
        AC_MSG_WARN([pkg-config not found, libfabric module will be disabled])
      ])
    ], [
      dnl Save original PKG_CONFIG_PATH
      ORIG_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      dnl If user specified a path, prepend it to PKG_CONFIG_PATH
      AS_IF([test "x$with_libfabric_path" != "xyes" && test "x$with_libfabric_path" != "xauto"], [
          PKG_CONFIG_PATH="$with_libfabric_path:$PKG_CONFIG_PATH"
          # if path is a directory, append /pkgconfig
          AS_IF([test -d "$with_libfabric_path/pkgconfig"], [
              PKG_CONFIG_PATH="$with_libfabric_path/pkgconfig:$ORIG_PKG_CONFIG_PATH"
          ])
          export PKG_CONFIG_PATH
      ])
      dnl Check for libfabric using pkg-config
      PKG_CHECK_MODULES([LIBFABRIC], [libfabric],
        [dnl Action if found
        enable_libfabric=yes
        dnl Add libfabric flags to LIBS and CFLAGS
        LIBS="$LIBS $LIBFABRIC_LIBS"
        CFLAGS="$CFLAGS $LIBFABRIC_CFLAGS"],
        [dnl Action if not found
        AC_MSG_RESULT([no])
        AS_IF([test "x$with_libfabric_path" != "xauto"], [
           dnl User explicitly requested libfabric, error out
           AC_MSG_ERROR([libfabric not found, but was explicitly requested with --with-libfabric=$with_libfabric_path])
        ], [
           dnl Otherwise, just warn and disable
           AC_MSG_WARN([libfabric not found. Will not build libfabric module.])
        ])]
      )
      dnl Restore original PKG_CONFIG_PATH
      PKG_CONFIG_PATH="$ORIG_PKG_CONFIG_PATH"
      export PKG_CONFIG_PATH
    ])
  ])
])
