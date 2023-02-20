![Logo](https://raw.githubusercontent.com/Dado1513/PAPIMonitor/master/papi-monitor.png)

 
[![Python Version](https://img.shields.io/badge/Python-3.5%2B-green.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Dado1513/AndroidApiMonitoring/blob/master/LICENSE)

**PAPIMonitor** (**P**ython **API** **Monitor** for Android apps) is a python tool based on [Frida](https://frida.re/docs/android/) for monitoring user-select APIs during the app execution.
The app should be installed within an emulator already connected through ADB to the pc host.
The user can choose to monitor a predefined list of APIs divided into several categories (e.g., Device Data, Device Info, SMS) or a custom list of APIs passed through the command line to the script.
The tool stores the invoked API, the parameters, the return value, and the line and file from where it was called.

Below is an example of output:
```json
{   
    "category": "Custom", 
    "class": "com.dave.popupre.MainActivity", 
    "method": "getText", 
    "args": [], 
    "calledFrom": "com.dave.popupre.MainActivity$1.onClick(MainActivity.java:26)", 
    "returnValue": "Hello Toast!", 
    "time": "03/09/2021, 14:43:06"
}

```

:warning: **Warning with Google Emulator**

| Google Emulator        | Ubuntu                   | Windows                  | MacOS                    |
|:----------------------:|:------------------------:|:------------------------:|:------------------------:|
| **7.x x86**            | :heavy_check_mark:       | :heavy_check_mark:       | :heavy_check_mark:       |
| **8.x x86**            | :heavy_check_mark:       | :heavy_check_mark:       | :heavy_check_mark:       |
| **9.0 x86**            | :heavy_check_mark:       | :heavy_check_mark:       | :heavy_check_mark:       |
| **10.0 x86**           | :heavy_check_mark:       | :heavy_check_mark:       | :heavy_check_mark:       |
| **11.0 x86**        | :heavy_check_mark:          | :heavy_check_mark:       | :heavy_check_mark:       |
| **12.0 x86**        | :heavy_check_mark:          | :heavy_check_mark:       | :heavy_check_mark:       |

:warning: Frida seems broken on Android 11-12 (x86_64) (Google Emulatore). 
- [issue-1917](https://github.com/frida/frida/issues/1917)
- [issue-1977](https://github.com/frida/frida/issues/1977)
- [issue-1982](https://github.com/frida/frida/issues/1982)

---

## Installation
General requirements:
```bash
sudo apt-get install libjpeg-dev zlib1g-dev
```

### Installation with pyenv and virtualenv
- Install [pyenv](https://github.com/pyenv/pyenv) and [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv)
```bash
pyenv install 3.8.0
pyenv virtualenv 3.8.0 papi-monitor
pyenv activate 3.8.0/envs/papi-monitor
pip3 install -r requirements
```

### Installation with virtualenv

- install virtualenv

```bash
sudo apt-get install python3-virtualenv
```
- activate virtualenv
```bash
virtualenv env
source env/bin/activate
```
- install requirements

```bash
pip install -r requirements
```

- Download frida-server in `resources/frida-server/`

## Post Installation
- adb in path file
- emulator/device already running and connect

---

## Usage

### Predefined Categories
- Device Data
- Device Info
- SMS
- System Manager
- Base64 encode/decode
- Dex Class Loader
- Network
- Crypto
- Crypto - Hash
- Binder
- IPC
- Database
- SharedPreferences
- WebView
- Java Native Interface
- Command
- Process
- FileSytem - Java


---

### Frida Script

A lot of Frida Script for Android can be found [here](https://github.com/Dado1513/frida-script-android).

---
