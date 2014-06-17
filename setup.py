#!/usr/bin/python

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp


version = imp.load_source('version', 'lib/version.py')
util = imp.load_source('version', 'lib/util.py')

if sys.version_info[:3] < (2, 6, 0):
    sys.exit("Error: Electrum requires Python version >= 2.6.0...")

usr_share = '/usr/share'
if not os.access(usr_share, os.W_OK):
    usr_share = os.getenv("XDG_DATA_HOME", os.path.join(os.getenv("HOME"), ".local", "share"))

data_files = []
if (len(sys.argv) > 1 and (sys.argv[1] == "sdist")) or (platform.system() != 'Windows' and platform.system() != 'Darwin'):
    print "Including all files"
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-exe.desktop']),
        (os.path.join(usr_share, 'app-install', 'icons/'), ['icons/electrum-exe.png'])
    ]
    if not os.path.exists('locale'):
        os.mkdir('locale')
    for lang in os.listdir('locale'):
        if os.path.exists('locale/%s/LC_MESSAGES/electrum.mo' % lang):
            data_files.append((os.path.join(usr_share, 'locale/%s/LC_MESSAGES' % lang), ['locale/%s/LC_MESSAGES/electrum.mo' % lang]))

appdata_dir = util.appdata_dir()
if not os.access(appdata_dir, os.W_OK):
    appdata_dir = os.path.join(usr_share, "electrum-exe")

data_files += [
    (appdata_dir, ["data/README"]),
    (os.path.join(appdata_dir, "cleanlook"), [
        "data/cleanlook/name.cfg",
        "data/cleanlook/style.css"
    ]),
    (os.path.join(appdata_dir, "sahara"), [
        "data/sahara/name.cfg",
        "data/sahara/style.css"
    ]),
    (os.path.join(appdata_dir, "dark"), [
        "data/dark/name.cfg",
        "data/dark/style.css"
    ])
]


setup(
    name="Electrum-EXE",
    version=version.ELECTRUM_VERSION,
    install_requires=['slowaes', 'ecdsa>=0.9', 'vtc_scrypt'],
    package_dir={
        'electrum_exe': 'lib',
        'electrum_exe_gui': 'gui',
        'electrum_exe_plugins': 'plugins',
    },
    scripts=['electrum-exe'],
    data_files=data_files,
    py_modules=[
        'electrum_exe.account',
        'electrum_exe.bitcoin',
        'electrum_exe.blockchain',
        'electrum_exe.bmp',
        'electrum_exe.commands',
        'electrum_exe.daemon',
        'electrum_exe.i18n',
        'electrum_exe.interface',
        'electrum_exe.mnemonic',
        'electrum_exe.msqr',
        'electrum_exe.network',
        'electrum_exe.plugins',
        'electrum_exe.pyqrnative',
        'electrum_exe.scrypt',
        'electrum_exe.simple_config',
        'electrum_exe.socks',
        'electrum_exe.synchronizer',
        'electrum_exe.transaction',
        'electrum_exe.util',
        'electrum_exe.verifier',
        'electrum_exe.version',
        'electrum_exe.wallet',
        'electrum_exe.wallet_bitkey',
        'electrum_exe_gui.gtk',
        'electrum_exe_gui.qt.__init__',
        'electrum_exe_gui.qt.amountedit',
        'electrum_exe_gui.qt.console',
        'electrum_exe_gui.qt.history_widget',
        'electrum_exe_gui.qt.icons_rc',
        'electrum_exe_gui.qt.installwizard',
        'electrum_exe_gui.qt.lite_window',
        'electrum_exe_gui.qt.main_window',
        'electrum_exe_gui.qt.network_dialog',
        'electrum_exe_gui.qt.password_dialog',
        'electrum_exe_gui.qt.qrcodewidget',
        'electrum_exe_gui.qt.receiving_widget',
        'electrum_exe_gui.qt.seed_dialog',
        'electrum_exe_gui.qt.transaction_dialog',
        'electrum_exe_gui.qt.util',
        'electrum_exe_gui.qt.version_getter',
        'electrum_exe_gui.stdio',
        'electrum_exe_gui.text',
        'electrum_exe_plugins.exchange_rate',
        'electrum_exe_plugins.labels',
        'electrum_exe_plugins.pointofsale',
        'electrum_exe_plugins.qrscanner',
        'electrum_exe_plugins.virtualkeyboard',
    ],
    description="Lightweight Execoin Wallet",
    author="fukukami",
    author_email="fukukami@github",
    license="GNU GPLv3",
    url="http://electrum.execoin.org",
    long_description="""Lightweight Execoin Wallet"""
)
