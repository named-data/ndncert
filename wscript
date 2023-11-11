# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

import os
from waflib import Utils

VERSION = '0.1.0'
APPNAME = 'ndncert'

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs'])
    opt.load(['default-compiler-flags',
              'coverage', 'sanitizers',
              'boost', 'openssl', 'sqlite3'],
             tooldir=['.waf-tools'])

    optgrp = opt.add_option_group('ndncert Options')
    optgrp.add_option('--with-tests', action='store_true', default=False,
                      help='Build unit tests')
    optgrp.add_option('--without-tools', action='store_false', default=True, dest='with_tools',
                      help='Do not build tools')

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs',
               'default-compiler-flags',
               'boost', 'openssl', 'sqlite3'])

    conf.env.WITH_TESTS = conf.options.with_tests
    conf.env.WITH_TOOLS = conf.options.with_tools

    # Prefer pkgconf if it's installed, because it gives more correct results
    # on Fedora/CentOS/RHEL/etc. See https://bugzilla.redhat.com/show_bug.cgi?id=1953348
    # Store the result in env.PKGCONFIG, which is the variable used inside check_cfg()
    conf.find_program(['pkgconf', 'pkg-config'], var='PKGCONFIG')

    pkg_config_path = os.environ.get('PKG_CONFIG_PATH', f'{conf.env.LIBDIR}/pkgconfig')
    conf.check_cfg(package='libndn-cxx', args=['libndn-cxx >= 0.8.1', '--cflags', '--libs'],
                   uselib_store='NDN_CXX', pkg_config_path=pkg_config_path)

    conf.check_sqlite3()
    conf.check_openssl(lib='crypto', atleast_version='1.1.1')

    conf.check_boost(lib='filesystem', mt=True)
    if conf.env.BOOST_VERSION_NUMBER < 107100:
        conf.fatal('The minimum supported version of Boost is 1.71.0.\n'
                   'Please upgrade your distribution or manually install a newer version of Boost.\n'
                   'For more information, see https://redmine.named-data.net/projects/nfd/wiki/Boost')

    if conf.env.WITH_TESTS:
        conf.check_boost(lib='unit_test_framework', mt=True, uselib_store='BOOST_TESTS')

    if conf.env.WITH_TOOLS:
        conf.check_boost(lib='program_options', mt=True, uselib_store='BOOST_TOOLS')

    conf.check_compiler_flags()

    # Loading "late" to prevent tests from being compiled with profiling flags
    conf.load('coverage')
    conf.load('sanitizers')

    # If there happens to be a static library, waf will put the corresponding -L flags
    # before dynamic library flags.  This can result in compilation failure when the
    # system has a different version of the ndncert library installed.
    conf.env.prepend_value('STLIBPATH', ['.'])

    conf.define_cond('HAVE_TESTS', conf.env.WITH_TESTS)
    conf.define('SYSCONFDIR', conf.env.SYSCONFDIR)
    # The config header will contain all defines that were added using conf.define()
    # or conf.define_cond().  Everything that was added directly to conf.env.DEFINES
    # will not appear in the config header, but will instead be passed directly to the
    # compiler on the command line.
    conf.write_config_header('src/detail/ndncert-config.hpp', define_prefix='NDNCERT_')

def build(bld):
    bld.shlib(
        target='ndn-cert',
        name='libndn-cert',
        vnum=VERSION,
        cnum=VERSION,
        source=bld.path.ant_glob('src/**/*.cpp'),
        use='BOOST NDN_CXX OPENSSL SQLITE3',
        includes='src',
        export_includes='src')

    if bld.env.WITH_TESTS:
        bld.recurse('tests')

    if bld.env.WITH_TOOLS:
        bld.recurse('tools')

    # Install header files
    srcdir = bld.path.find_dir('src')
    bld.install_files('${INCLUDEDIR}/ndncert',
                      srcdir.ant_glob('**/*.hpp'),
                      cwd=srcdir,
                      relative_trick=True)
    bld.install_files('${INCLUDEDIR}/ndncert/detail', 'src/detail/ndncert-config.hpp')

    # Install sample configs
    bld.install_files('${SYSCONFDIR}/ndncert',
                      ['ca.conf.sample',
                       'client.conf.sample',
                       'ndncert-mail.conf.sample'])

    bld(features='subst',
        source='libndn-cert.pc.in',
        target='libndn-cert.pc',
        install_path='${LIBDIR}/pkgconfig',
        VERSION=VERSION)

    bld(features='subst',
        name='ndncert-send-email-challenge',
        source='ndncert-send-email-challenge.py',
        target='bin/ndncert-send-email-challenge',
        install_path='${BINDIR}',
        chmod=Utils.O755)

    if Utils.unversioned_sys_platform() == 'linux':
        bld(features='subst',
            name='systemd-units',
            source='systemd/ndncert-ca.service.in',
            target='systemd/ndncert-ca.service')

def dist(ctx):
    ctx.algo = 'tar.xz'

def distcheck(ctx):
    ctx.algo = 'tar.xz'
