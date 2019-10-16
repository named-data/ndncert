# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

from waflib import Context, Utils
import os

VERSION = '0.1.0'
APPNAME = 'ndncert'
GIT_TAG_PREFIX = 'ndncert-'

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs'])
    opt.load(['default-compiler-flags', 'coverage', 'sanitizers',
              'boost', 'openssl', 'sqlite3',
              'doxygen', 'sphinx_build'],
             tooldir=['.waf-tools'])

    opt_group = opt.add_option_group('ndncert Options')
    opt_group.add_option('--with-tests', action='store_true', default=False,
                         help='Build unit tests')

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs',
               'default-compiler-flags',
               'boost', 'openssl', 'sqlite3',
               'doxygen', 'sphinx_build'])

    conf.env.WITH_TESTS = conf.options.with_tests

    if 'PKG_CONFIG_PATH' not in os.environ:
        os.environ['PKG_CONFIG_PATH'] = Utils.subst_vars('${LIBDIR}/pkgconfig', conf.env)
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'], uselib_store='NDN_CXX')

    conf.check_sqlite3()
    conf.check_openssl(lib='crypto', atleast_version=0x1000200f) # 1.0.2

    boost_libs = ['system', 'program_options', 'filesystem']
    if conf.env.WITH_TESTS:
        boost_libs.append('unit_test_framework')

    conf.check_boost(lib=boost_libs, mt=True)
    if conf.env.BOOST_VERSION_NUMBER < 105800:
        conf.fatal('Minimum required Boost version is 1.58.0\n'
                   'Please upgrade your distribution or manually install a newer version of Boost'
                   ' (https://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)')

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
    conf.write_config_header('src/ndncert-config.hpp')

def build(bld):
    bld.shlib(target='ndn-cert',
              source=bld.path.ant_glob('src/**/*.cpp'),
              vnum=VERSION,
              cnum=VERSION,
              use='NDN_CXX BOOST OPENSSL SQLITE3',
              includes='src',
              export_includes='src',
              install_path='${LIBDIR}')

    bld(features='subst',
        source='libndn-cert.pc.in',
        target='libndn-cert.pc',
        install_path = '${LIBDIR}/pkgconfig',
        PREFIX       = bld.env['PREFIX'],
        INCLUDEDIR   = '${INCLUDEDIR}/ndncert',
        VERSION      = VERSION)

    bld.recurse('tools')
    bld.recurse('tests')

    bld.install_files(
        dest='${INCLUDEDIR}/ndncert',
        files=bld.path.ant_glob('src/**/*.hpp'),
        cwd=bld.path.find_dir('src'),
        relative_trick=True)

    bld.install_files(
        dest='${INCLUDEDIR}/ndncert',
        files=bld.path.get_bld().ant_glob('src/**/*.hpp'),
        cwd=bld.path.get_bld().find_dir('src'),
        relative_trick=False)

    bld.install_files('${SYSCONFDIR}/ndncert', ['ca.conf.sample',
                                                'client.conf.sample',
                                                'ndncert-mail.conf.sample'])

    bld(features='subst',
        name='ndncert-send-email-challenge',
        source='ndncert-send-email-challenge.py',
        target='bin/ndncert-send-email-challenge',
        install_path='${BINDIR}',
        chmod=Utils.O755)

    if Utils.unversioned_sys_platform() == 'linux':
        bld(features='subst',
            name='ndncert-server.service',
            source='systemd/ndncert-server.service.in',
            target='systemd/ndncert-server.service')
