#!/usr/bin/env python
# coding: utf-8

import logging
import os
import re
import shutil
import subprocess
import time

from typing import Optional, Union, List


class ADB(object):

    def __init__(self, device: str = None, debug: bool = False):
        """
        Android Debug Bridge (adb) object constructor.

        :param device: The name of the Android device (serial number) for which to execute adb commands. Can be
                       omitted if there is only one Android device connected to adb.
        :param debug: When set to True, more debug messages will be shown for each executed operation.
        """

        self.logger = logging.getLogger('{0}.{1}'.format(__name__, self.__class__.__name__))

        self._device = device

        if debug:
            self.logger.setLevel(logging.DEBUG)

        # If adb executable is not added to PATH variable, it can be specified by using the
        # ADB_PATH environment variable.
        if 'ADB_PATH' in os.environ:
            self.adb_path: str = os.environ['ADB_PATH']
        else:
            self.adb_path: str = 'adb'

        if not self.is_available():
            raise FileNotFoundError('Adb executable is not available! Make sure to have adb (Android Debug Bridge) '
                                    'installed and added to the PATH variable, or specify the adb path by using the '
                                    'ADB_PATH environment variable.')

    @property
    def target_device(self) -> str:
        return self._device

    @target_device.setter
    def target_device(self, new_device: str):
        self._device = new_device

    def is_available(self) -> bool:
        """
        Check if adb executable is available.

        :return: True if abd executable is available for usage, False otherwise.
        """

        return shutil.which(self.adb_path) is not None

    def execute(self, command: List[str], is_async: bool = False, timeout: Optional[int] = None) -> Optional[str]:
        """
        Execute an adb command and return the output of the command as a string.

        :param command: The command to execute, formatted as a list of strings.
        :param is_async: When set to True, the adb command will run in background and the program will continue its
                         execution. If False (default), the program will wait until the adb command returns a result.
        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: The (string) output of the command. If the method is called with the parameter is_async = True,
                 None will be returned.
        """

        if not isinstance(command, list) or any(not isinstance(command_token, str) for command_token in command):
            raise TypeError('The command to execute should be passed as a list of strings')

        if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
            raise ValueError('If a timeout is provided, it must be a positive integer')

        if is_async and timeout:
            raise RuntimeError('The timeout cannot be used when executing the program in background')

        try:
            # Use the specified Android device serial number (if any).
            if self.target_device:
                command[0:0] = ['-s', self.target_device]

            command.insert(0, self.adb_path)
            self.logger.debug('Running command `{0}` (async={1}, timeout={2})'
                              .format(' '.join(command), is_async, timeout))

            if is_async:
                # Adb command will run in background, nothing to return.
                subprocess.Popen(command)
                return None
            else:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = process.communicate(timeout=timeout)[0].strip().decode(errors='backslashreplace')
                if process.returncode != 0:
                    raise subprocess.CalledProcessError(process.returncode, command, output.encode())
                self.logger.debug('Command `{0}` successfully returned: {1}'.format(' '.join(command), output))

                # This is needed to make sure the adb command actually terminated before continuing the execution.
                time.sleep(1)

                return output
        except subprocess.TimeoutExpired as e:
            self.logger.error('Command `{0}` timed out: {1}'.format(
                ' '.join(command), e.output.decode(errors='backslashreplace') if e.output else e))
            raise
        except subprocess.CalledProcessError as e:
            self.logger.error('Command `{0}` exited with error: {1}'.format(
                ' '.join(command), e.output.decode(errors='backslashreplace') if e.output else e))
            raise
        except Exception as e:
            self.logger.error('Generic error during `{0}` command execution: {1}'.format(' '.join(command), e))
            raise

    def get_version(self, timeout: Optional[int] = None) -> str:
        """
        Get the version of the installed adb.

        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: A string containing the version of the installed adb.
        """

        output = self.execute(['version'], timeout=timeout)

        match = re.search(r'version\s(\S+)', output)
        if match:
            return match.group(1)
        else:
            raise RuntimeError('Unable to determine adb version')

    def get_available_devices(self, timeout: Optional[int] = None) -> List[str]:
        """
        Get a list with the serials of the devices currently connected to adb.

        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: A list of strings, each string is a device serial number.
        """

        output = self.execute(['devices'], timeout=timeout)

        devices = []
        for line in output.splitlines():
            tokens = line.strip().split()
            if len(tokens) == 2 and tokens[1] == 'device':
                # Add to the list the name / ip and port of the device.
                devices.append(tokens[0])
        return devices

    def shell(self, command: List[str], is_async: bool = False, timeout: Optional[int] = None) -> Optional[str]:
        """
        Execute an adb shell command on the Android device connected through adb and return the output
        of the command as a string.

        :param command: The command to execute, formatted as a list of strings.
        :param is_async: When set to True, the adb shell command will run in background and the program will continue
                         its execution. If False (default), the program will wait until the adb shell command returns
                         a result. This can be useful when running background scripts on the Android device.
        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: The (string) output of the command. If the method is called with the parameter is_async = True,
                 None will be returned.
        """

        if not isinstance(command, list) or any(not isinstance(command_token, str) for command_token in command):
            raise TypeError('The command to execute should be passed as a list of strings')

        command.insert(0, 'shell')

        return self.execute(command, is_async=is_async, timeout=timeout)

    def get_property(self, property_name: str, timeout: Optional[int] = None) -> str:
        """
        Get the value of a property on the Android device connected through adb.

        :param property_name: The name of the property.
        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: The value of the property.
        """

        return self.shell(['getprop', property_name], timeout=timeout)

    def get_device_sdk_version(self, timeout: Optional[int] = None) -> int:
        """
        Get the version of the SDK installed on the Android device (e.g., 23 for Android Marshmallow).

        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: An int with the version number.
        """

        return int(self.get_property('ro.build.version.sdk', timeout=timeout))

    def wait_for_device(self, timeout: Optional[int] = None) -> None:
        """
        Wait until the Android device connected through adb is ready to receive commands.

        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        """

        self.execute(['wait-for-device'], timeout=timeout)

    def kill_server(self, timeout: Optional[int] = None) -> None:
        """
        Kill the adb server if it is running.

        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        """

        self.execute(['kill-server'], timeout=timeout)

    def connect(self, host: str = None, timeout: Optional[int] = None) -> str:
        """
        Start an adb server and (optionally) connect to an Android device.

        :param host: (Optional) Host address of the Android device (in host[:port] format). This parameter is not
                     needed in simple scenarios when connecting to the default emulator or to a device connected
                     through usb cable, since in this case the connection is automatic.
        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: The string with the result of the connect operation.
        """

        if host:
            connect_cmd = ['connect', host]
        else:
            connect_cmd = ['start-server']

        output = self.execute(connect_cmd, timeout=timeout)

        # Make sure the connect operation ended successfully.
        if output and 'unable to connect' in output.lower():
            raise RuntimeError('Something went wrong during the connect operation: {0}'.format(output))
        else:
            return output

    def remount(self, timeout: Optional[int] = None) -> str:
        """
        Remount system partitions in writable mode (system partitions are read-only by default). This command needs
        adb with root privileges.

        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        :return: The string with the result of the remount operation.
        """

        output = self.execute(['remount'], timeout=timeout)

        # Make sure the remount operation ended successfully.
        if output and 'remount succeeded' in output.lower():
            return output
        else:
            raise RuntimeError('Something went wrong during the remount operation: {0}'.format(output))

    def reboot(self, timeout: Optional[int] = None) -> None:
        """
        Reboot the Android device connected through adb.

        :param timeout: How many seconds to wait for the command to finish execution before throwing an exception.
        """

        return self.execute(['reboot'], timeout=timeout)

    def push_file(self, host_path: Union[str, List[str]], device_path: str, timeout: Optional[int] = None) -> str:
        """
        Copy a file (or a list of files) from the computer to the Android device connected through adb.

        :param host_path: The path of the file on the host computer. This parameter also accepts a list of paths
                          (strings) to copy more files at the same time.
        :param device_path: The path on the Android device where the file(s) should be copied.
        :param timeout: How many seconds to wait for the file copy operation before throwing an exception.
        :return: The string with the result of the copy operation.
        """

        # Make sure the files to copy exist on the host computer.
        if isinstance(host_path, list):
            for p in host_path:
                if not os.path.exists(p):
                    raise FileNotFoundError('Cannot copy "{0}" to the Android device: no such file or directory'
                                            .format(p))

        if isinstance(host_path, str) and not os.path.exists(host_path):
            raise FileNotFoundError('Cannot copy "{0}" to the Android device: no such file or directory'
                                    .format(host_path))

        push_cmd = ['push']
        if isinstance(host_path, list):
            push_cmd.extend(host_path)
        else:
            push_cmd.append(host_path)

        push_cmd.append(device_path)

        output = self.execute(push_cmd, timeout=timeout)

        # Make sure the push operation ended successfully.
        match = re.search(r'\d+ files? pushed\.', output.splitlines()[-1])
        if match:
            return output
        else:
            raise RuntimeError('Something went wrong during the file push operation')

    def pull_file(self, device_path: Union[str, List[str]], host_path: str, timeout: Optional[int] = None) -> str:
        """
        Copy a file (or a list of files) from the Android device to the computer connected through adb.

        :param device_path: The path of the file on the Android device. This parameter also accepts a list of paths
                            (strings) to copy more files at the same time.
        :param host_path: The path on the host computer where the file(s) should be copied. If multiple files are
                          copied at the same time, this path should refer to an existing directory on the host.
        :param timeout: How many seconds to wait for the file copy operation before throwing an exception.
        :return: The string with the result of the copy operation.
        """

        # When copying multiple files at the same time, make sure the host path refers to an existing directory.
        if isinstance(device_path, list) and not os.path.isdir(host_path):
            raise NotADirectoryError('When copying multiple files, the destination host path should be an '
                                     'existing directory: "{0}" directory was not found'.format(host_path))

        # Make sure the destination directory on the host exists (adb won't create the missing directories specified
        # on the host path). For example, if test/ directory exists on host, it can be used, but test/nested/ can be
        # used only if it already exists on the host, otherwise adb won't create the nested/ directory.
        if not os.path.isdir(os.path.dirname(host_path)):
            raise NotADirectoryError('The destination host directory "{0}" was not found'
                                     .format(os.path.dirname(host_path)))

        pull_cmd = ['pull']
        if isinstance(device_path, list):
            pull_cmd.extend(device_path)
        else:
            pull_cmd.append(device_path)

        pull_cmd.append(host_path)

        output = self.execute(pull_cmd, timeout=timeout)

        # Make sure the pull operation ended successfully.
        match = re.search(r'\d+ files? pulled\.', output.splitlines()[-1])
        if match:
            return output
        else:
            raise RuntimeError('Something went wrong during the file pull operation')

    def install_app(self, apk_path: str, replace_existing: bool = False,
                    grant_permissions: bool = False, timeout: Optional[int] = None):
        """
        Install an application into the Android device.

        :param apk_path: The path on the host computer to the application file to be installed.
        :param replace_existing: When set to True, any old version of the application installed on the Android device
                                 will be replaced by the new application being installed.
        :param grant_permissions: When set to True, all the runtime permissions of the application will be granted.
        :param timeout: How many seconds to wait for the install operation before throwing an exception.
        :return: The string with the result of the install operation.
        """

        # Make sure the application to install is an existing file on the host computer.
        if not os.path.isfile(apk_path):
            raise FileNotFoundError('"{0}" apk file was not found'.format(apk_path))

        install_cmd = ['install']

        # Additional installation flags.
        if replace_existing:
            install_cmd.append('-r')
        if grant_permissions and self.get_device_sdk_version() >= 23:
            # Runtime permissions exist since SDK version 23 (Android Marshmallow).
            install_cmd.append('-g')

        install_cmd.append(apk_path)

        output = self.execute(install_cmd, timeout=timeout)

        # Make sure the install operation ended successfully. Complete list of error messages:
        # https://android.googlesource.com/platform/frameworks/base/+/lollipop-release/core/java/android/content/pm/PackageManager.java
        match = re.search(r'Failure \[.+?\]', output, flags=re.IGNORECASE)
        if not match:
            return output
        else:
            raise RuntimeError('Application installation failed: {0}'.format(match.group()))

    def uninstall_app(self, package_name: str, timeout: Optional[int] = None):
        """
        Uninstall an application from the Android device.

        :param package_name: The package name of the application to uninstall.
        :param timeout: How many seconds to wait for the uninstall operation before throwing an exception.
        :return: The string with the result of the uninstall operation.
        """

        uninstall_cmd = ['uninstall', package_name]

        output = self.execute(uninstall_cmd, timeout=timeout)

        # Make sure the uninstall operation ended successfully. Complete list of error messages:
        # https://android.googlesource.com/platform/frameworks/base/+/lollipop-release/core/java/android/content/pm/PackageManager.java
        match = re.search(r'Failure \[.+?\]', output, flags=re.IGNORECASE)
        if not match:
            return output
        else:
            raise RuntimeError('Application removal failed: {0}'.format(match.group()))
