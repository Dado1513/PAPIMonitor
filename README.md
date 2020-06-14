# AndroidApiMonitoring
[![Python Version](https://img.shields.io/badge/Python-3.5%2B-green.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Dado1513/AndroidApiMonitoring/blob/master/LICENSE)


### Installation

- install virtualenv

```bash
pip install virtualenv
```

- install requirements

```bash
pip install -r requirements
```

- adb in path file
- emulator/device already running and connect

### Usage

![Help](https://github.com/Dado1513/AndroidApiMonitoring/blob/master/img_repo/command_help.gif)

Usage example:

![Usage Example](https://github.com/Dado1513/AndroidApiMonitoring/blob/master/img_repo/usage_example.gif)

--------------------

Usage script frida in a general way:

```bash
frida -U -l script.js -f "packagename" --no-pause
```
