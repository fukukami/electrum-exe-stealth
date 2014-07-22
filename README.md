Electrum-EXE - lightweight Execoin client

Licence: GNU GPL v3  
Author: Thomas Voegtlin  
Contributors: pooler, wozz, fukukami  
Language: Python  
Homepage: https://electrum-exe.org/stealth/  


1. GETTING STARTED
------------------

To run Electrum from this directory, just do:

    ./electrum-exe

If you install Electrum on your system, you can run it from any
directory:

    sudo python setup.py install
    electrum-exe

If you don't want to install Exectrum globally, see section `3. FINE-TUNING YOUR INSTALLATION`



2. HOW OFFICIAL PACKAGES ARE CREATED
------------------------------------

    python mki18n.py
    pyrcc4 icons.qrc -o gui/qt/icons_rc.py
    python setup.py sdist --format=zip,gztar

On Mac OS X:

    # On port based installs
    sudo python setup-release.py py2app

    # On brew installs
    ARCHFLAGS="-arch i386 -arch x86_64" sudo python setup-release.py py2app --includes sip

    sudo hdiutil create -fs HFS+ -volname "Electrum-EXE" -srcfolder dist/Electrum-exe.app dist/electrum-exe-VERSION-macosx.dmg



3. FINE-TUNING YOUR INSTALLATION (ADVANCED)
-------------------------------------------

Electrum requires these python libraries:

* PyQt4
* ecdsa
* slowaes

### Install requirements on Linux

You have 3 installation options:

1. *Easiest*: find and install libraries using your OS's package manager.
    Name and availability of packages depends on the distribution you are running.

2. *Recommended*: Partially isolated environment using virtualenv.  
    Initialize python virtual environment into`venv` directory:
    
        virtualenv venv --system-site-packages
    
    or if you are on ArchLinux:
    
        virtualenv2 venv --system-site-packages
    
    Activate virtualenv with
    
        source venv/bin/activate
    
    Install slowaes and ecdsa:
    
        pip install slowaes -v --pre
        pip install ecdsa
    
    Then, to save your time from compiling pyqt4 from source, install PyQt4 package using your package manager. On Ubuntu, use:
    
        sudo apt-get install python-qt4
    
    if you are on ArchLinux:
    
        sudo pacman -S python2-pyqt4
    
    
3. The hard way: Fully isolated environment using virtualenv  
    Initialize python virtual environment into `venv` directory:
    
        virtualenv venv
    
    or if you are on ArchLinux:
    
        virtualenv2 venv
    
    Activate virtualenv with
    
        source venv/bin/activate
    
    Install slowaes and ecdsa:
    
        pip install slowaes -v --pre
        pip install ecdsa
    
    Then you can compile PyQt4 from source.  
    Detailed instructions can be found in [PyQt4 installation guide](http://pyqt.sourceforge.net/Docs/PyQt4/installation.html)
    
When dependencies are ready, install like in section `1. GETTING STARTED`:

    python setup.py install
    electrum-exe
    
    
4. TROUBLESHOOTING AND BUG REPORTING
------------------------------------
To see the log, run Electrum with -v option:

    electrum-exe -v
