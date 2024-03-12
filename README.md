# Virtual Smart Card Architecture

Virtual Smart Card Architecture is an umbrella project for various
projects concerned with the emulation of different types of smart card readers
or smart cards themselves.

Environment setup:
```bash
	python3 -m venv /path/to/new/virtual/environment
	source /path/to/new/virtual/environment/bin/activate
```

On the root folder install the required python packages:
```bash
	pip install -r requirements.txt
```

Currently the following projects are part of Virtual Smart Card Architecture: 

- [Virtual Smart Card](http://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html)
- [Remote Smart Card Reader](http://frankmorgner.github.io/vsmartcard/remote-reader/README.html)
- [Android Smart Card Emulator](http://frankmorgner.github.io/vsmartcard/ACardEmulator/README.html)
- [PC/SC Relay](http://frankmorgner.github.io/vsmartcard/pcsc-relay/README.html)
- [USB CCID Emulator](http://frankmorgner.github.io/vsmartcard/ccid/README.html)

Please refer to [our project's website](http://frankmorgner.github.io/vsmartcard) for more information.

[![GitHub CI status](https://img.shields.io/github/actions/workflow/status/frankmorgner/vsmartcard/ci.yml?branch=master&label=Ubuntu%2FmacOS&logo=github)](https://github.com/frankmorgner/vsmartcard/actions/workflows/ci.yml?branch=master) [![AppVeyor CI status](https://img.shields.io/appveyor/ci/frankmorgner/vsmartcard/master.svg?label=Windows&logo=appveyor)](https://ci.appveyor.com/project/frankmorgner/vsmartcard) [![Coverity Scan status](https://img.shields.io/coverity/scan/3987.svg?label=Coverity%20Scan)](https://scan.coverity.com/projects/3987)
