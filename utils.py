from loguru import logger
from adb import ADB
from androguard.core.bytecodes.apk import APK
import time
import json
import os


def push_and_start_frida_server(adb: ADB):
    """
    Push and start adb server on device
    Parameters
    ----------
    adb

    Returns
    -------

    """
    frida_server = os.path.join(
        os.path.dirname(__file__), "resources", "frida-server-15", "frida-server"
    )

    try:
        adb.execute(["root"])
    except Exception as e:
        adb.kill_server()
        logger.error("Error on adb {}".format(e))
    logger.info("Push frida server")
    try:
        adb.push_file(frida_server, "/data/local/tmp")
    except Exception as e:
        pass
    logger.info("Add execution permission to frida-server")
    chmod_frida = ["chmod 755 /data/local/tmp/frida-server"]
    adb.shell(chmod_frida)
    logger.info("Start frida server")
    start_frida = ["cd /data/local/tmp && ./frida-server &"]
    adb.shell(start_frida, is_async=True)
    time.sleep(4)


def push_and_start_frida_server_google_emulator(adb: ADB):
    """

    Parameters
    ----------
    adb

    Returns
    -------

    """
    frida_server = os.path.join(
        os.path.dirname(__file__), "resources", "frida-server-15", "frida-server"
    )

    logger.info("Push frida-server")
    try:
        adb.push_file(frida_server, "/sdcard")
        adb.shell_su("mv /sdcard/frida-server /data/local/tmp/frida-server")
    except Exception as e:
        pass

    cmd_set_enforce = "setenforce 0"
    adb.shell_su(cmd_set_enforce)

    cmd_enforce_echo = "echo 0 > /sys/fs/selinux/enforce"
    adb.shell_su(cmd_enforce_echo)

    chmod_frida = "chmod 755 /data/local/tmp/frida-server"
    adb.shell_su(chmod_frida)
    logger.info("Start frida server")
    start_frida = "/data/local/tmp/frida-server &"
    adb.shell_su(start_frida, is_async=True)
    time.sleep(4)


def install_app_and_install_frida(app_path, is_google_emulator: bool = False):
    """
        Install app and Frida script
    Parameters
    ----------
    app_path

    Returns
    -------

    """
    app = APK(app_path)
    package_name = app.get_package()
    logger.info("Start ADB")
    adb = ADB()
    logger.info("Install APP")
    adb.install_app(app_path)
    logger.info("Frida Initialized")
    # if not is_google_emulator:
    #    push_and_start_frida_server(adb)
    # else:
    #    push_and_start_frida_server_google_emulator(adb)
    return package_name


def create_script_frida(list_api_to_monitoring: list, path_frida_script_template: str):
    """

    Parameters
    ----------
    list_api_to_monitoring
    path_frida_script_template

    Returns
    -------

    """
    with open(path_frida_script_template) as frida_script_file:
        script_frida_template = frida_script_file.read()

    script_frida = ""
    for tuple_class_method in list_api_to_monitoring:
        script_frida += (
            script_frida_template.replace(
                "class_name", '"' + tuple_class_method[0] + '"'
            ).replace("method_name", '"' + tuple_class_method[1] + '"')
            + "\n\n"
        )
    return script_frida


def create_adb_and_start_frida(package_name, is_google_emulator: bool = False):
    """

    Parameters
    ----------
    package_name

    Returns
    -------

    """
    logger.debug(f"App Already Installed, start to monitoring ${package_name}")
    adb = ADB()
    logger.debug("Frida Initialize")
    # if not is_google_emulator:
    #    push_and_start_frida_server(adb)
    # else:
    #    push_and_start_frida_server_google_emulator(adb)
    return package_name


def create_json_custom(list_api_to_monitoring):
    """

    Parameters
    ----------
    list_api_to_monitoring

    Returns
    -------

    """
    dict_category_custom = {"Category": "Custom", "HookType": "Java", "hooks": []}

    for api in list_api_to_monitoring:
        dict_method = {"clazz": api[0], "method": api[1]}
        dict_category_custom["hooks"].append(dict_method)

    return dict_category_custom


def create_json_api_monitor(json_list_api_file: str):
    """

    Parameters
    ----------
    json_list_api_file

    Returns
    -------

    """

    if not os.path.exists(json_list_api_file):
        return None

    # load file
    json_list_api = json.load(open(json_list_api_file, "r"))

    api_monitor = []
    dict_template = {"Category": "",  "HookType": "Java", "hooks": []}
    dict_data_category = {}
    for api in json_list_api:

        category = api["category"]
        clazz = api["className"]
        method = api["methodName"]
        # logger.debug(f"{category} {clazz} {method}")

        if category.lower() in dict_data_category:
            dict_data_category[category.lower()]["hooks"].append({"clazz": clazz, "method": method})
            # monitor_api_config["hooks"].append({"clazz": clazz, "method": method})
            # dict_data_category[category.lower()] = monitor_api_config

        else:
            monitor_api_config = {
                "Category": category.lower(),
                "HookType": "Java",
                "hooks": [{"clazz": clazz, "method": method}]
            }
            dict_data_category[category.lower()] = monitor_api_config

    for key, item in dict_data_category.items():
        api_monitor.append(item)
    return api_monitor





def read_api_to_monitoring(file_api_to_monitoring):
    """

    Parameters
    ----------
    file_api_to_monitoring

    Returns
    -------

    """
    if os.path.exists(file_api_to_monitoring):
        list_api_to_monitoring = []
        content = []
        with open(file_api_to_monitoring) as file_api:
            content = file_api.readlines()
        content = [x.strip() for x in content]
        for class_method in content:
            list_api_to_monitoring.append(
                (class_method.split(",")[0], class_method.split(",")[1])
            )
        return list_api_to_monitoring
    else:
        return None
