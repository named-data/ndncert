# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION = "0.1.0"
APPNAME = "ndncert"
BUGREPORT = "https://redmine.named-data.net/projects/ndncert"
GIT_TAG_PREFIX = "ndncert-"

from waflib import Context, Utils
import os

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs'])
    opt.load(['boost', 'default-compiler-flags', 'sqlite3',
              'coverage', 'sanitizers',
              'doxygen', 'sphinx_build'],
             tooldir=['.waf-tools'])

    certopt = opt.add_option_group("ndncert options")
    certopt.add_option('--with-tests', action='store_true', default=False,
                       help='Build unit tests')

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs',
               'boost', 'default-compiler-flags', 'sqlite3',
               'doxygen', 'sphinx_build'])

    if 'PKG_CONFIG_PATH' not in os.environ:
        os.environ['PKG_CONFIG_PATH'] = Utils.subst_vars('${LIBDIR}/pkgconfig', conf.env)
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    USED_BOOST_LIBS = ['system', 'filesystem', 'iostreams',
                       'program_options', 'thread', 'log', 'log_setup']

    conf.env['WITH_TESTS'] = conf.options.with_tests
    if conf.env['WITH_TESTS']:
        USED_BOOST_LIBS += ['unit_test_framework']
        conf.define('HAVE_TESTS', 1)

    conf.check_boost(lib=USED_BOOST_LIBS, mt=True)
    if conf.env.BOOST_VERSION_NUMBER < 105800:
        conf.fatal('Minimum required Boost version is 1.58.0\n'
                   'Please upgrade your distribution or manually install a newer version of Boost'
                   ' (https://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)')

    conf.check_compiler_flags()

    # Loading "late" to prevent tests from being compiled with profiling flags
    conf.load('coverage')

    conf.load('sanitizers')

    conf.define('SYSCONFDIR', conf.env['SYSCONFDIR'])

    # If there happens to be a static library, waf will put the corresponding -L flags
    # before dynamic library flags.  This can result in compilation failure when the
    # system has a different version of the ndncert library installed.
    conf.env['STLIBPATH'] = ['.'] + conf.env['STLIBPATH']

    conf.write_config_header('src/ndncert-config.hpp')

def build(bld):
    bld.shlib(target='ndn-cert',
              source=bld.path.ant_glob('src/**/*.cpp'),
              vnum=VERSION,
              cnum=VERSION,
              use='NDN_CXX BOOST',
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
        files=bld.path.ant_glob(['src/**/*.hpp', 'src/**/*.h']),
        cwd=bld.path.find_dir('src'),
        relative_trick=True)

    bld.install_files(
        dest='${INCLUDEDIR}/ndncert',
        files=bld.path.get_bld().ant_glob(['src/**/*.hpp']),
        cwd=bld.path.get_bld().find_dir('src'),
        relative_trick=False)

    bld.install_files("${SYSCONFDIR}/ndncert", "ca.conf.sample")
    bld.install_files("${SYSCONFDIR}/ndncert", "client.conf.sample")
    bld.install_files("${SYSCONFDIR}/ndncert", "ndncert-mail.conf.sample")

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
