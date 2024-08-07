# PAPIMonitor
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
---
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

---
### Demo

![DEMO](https://github.com/Dado1513/PAPIMonitor/blob/master/img_repo/papimonitor.gif)

--------------------
