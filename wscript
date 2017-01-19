# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION = "0.1.0"
APPNAME = "ndncert"
BUGREPORT = "http://redmine.named-data.net/projects/ndncert"
GIT_TAG_PREFIX = "ndncert"

from waflib import Logs, Utils, Context
import os

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs'])
    opt.load(['boost', 'default-compiler-flags', 'sqlite3',
              'coverage', 'sanitizers',
              'doxygen', 'sphinx_build'], tooldir=['.waf-tools'])

    syncopt = opt.add_option_group ("ndncert options")
    syncopt.add_option('--with-tests', action='store_true', default=False, dest='with_tests',
                       help='''build unit tests''')

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
    if conf.env.BOOST_VERSION_NUMBER < 105400:
        Logs.error("Minimum required boost version is 1.54.0")
        Logs.error("Please upgrade your distribution or install custom boost libraries" +
                    " (https://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)")
        return

    # Loading "late" to prevent tests to be compiled with profiling flags
    conf.load('coverage')

    conf.load('sanitizers')

    conf.write_config_header('src/ndncert-config.hpp')

def build(bld):
    core = bld(
        target = "objects",
        features=['cxx'],
        source =  bld.path.ant_glob(['src/**/*.cpp']),
        use = 'NDN_CXX BOOST',
        includes = ['src'],
        export_includes=['src'],
    )

    bld.recurse('tests')
