import frida
import os
import logging
import sys
import time
from adb import ADB
from androguard.core.bytecodes.apk import APK
import json 
from datetime import datetime
import argparse

if 'LOG_LEVEL' in os.environ:
    log_level = os.environ['LOG_LEVEL']
else:
    log_level = logging.INFO

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s> [%(levelname)s][%(name)s][%(funcName)s()] %(message)s',
                        datefmt='%d/%m/%Y %H:%M:%S', level=log_level)


file_log_frida = os.path.join(os.getcwd(), "logs")


def on_message(message, data):
    file_log = open(file_log_frida, "a")
    if message['type'] == 'send':
        if "Error" not in str(message["payload"]):
            message_new = message["payload"]
            message_new["time"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            file_log.write(str(message_new) + "\n")
            logger.info(str(message_new)+"\n")
    file_log.close()



def push_and_start_frida_server(adb: ADB):
    """
    Push and start adb server on device
    Parameters
    ----------
    adb

    Returns
    -------

    """
    frida_server = os.path.join(os.getcwd(), "resources", "frida-server", "frida-server")

    try:
        adb.execute(['root'])
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


def read_api_to_monitoring(file_api_to_monitoring):
    if os.path.exists(file_api_to_monitoring):
        list_api_to_monitoring = []
        content = []
        with open(file_api_to_monitoring) as file_api:
            content = file_api.readlines()
        content = [x.strip() for x in content]
        for class_method in content:
            list_api_to_monitoring.append((class_method.split(",")[0], class_method.split(",")[1]))
        return list_api_to_monitoring
    else:
        return None


def create_script_frida(list_api_to_monitoring: list, path_frida_script_template: str):
    with open(path_frida_script_template) as frida_script_file:
        script_frida_template = frida_script_file.read()

    script_frida = ""
    for tuple_class_method in list_api_to_monitoring:
        script_frida += script_frida_template.replace("class_name", "\"" + tuple_class_method[0] + "\""). \
                            replace("method_name", "\"" + tuple_class_method[1] + "\"") + "\n\n"
    return script_frida


def create_list_api_from_file(list_file_api_to_monitoring):
    list_api_to_monitoring_complete = list()
    for file_api_to_monitoring in list_file_api_to_monitoring:
        list_api_to_monitoring = read_api_to_monitoring(file_api_to_monitoring)
        list_api_to_monitoring_complete.extend(list_api_to_monitoring)
    return list_api_to_monitoring_complete


def install_app_and_install_frida(app_path):
    app = APK(app_path)
    package_name = app.get_package()
    logger.info("Start ADB")
    adb = ADB()
    logger.info("Install APP")
    adb.install_app(app_path)
    logger.info("Frida Initialize")
    push_and_start_frida_server(adb)
    return package_name

def create_adb_and_start_frida(package_name):
    logger.info(f"App Already Installed, start to monitoring ${package_name}")
    adb = ADB()
    logger.info("Frida Initialize")
    push_and_start_frida_server(adb)
    return package_name

def main(app_path, list_api_to_monitoring, app_to_install=True, store_script=False):
    
    print(list_file_api_to_monitoring)  
    # return
    
    if app_to_install:
        package_name = install_app_and_install_frida(app_path)
    else:
        package_name = create_adb_and_start_frida(app_path)

    pid = None
    device = None
    session = None
    
    try:
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        session = device.attach(pid)
    except Exception as e:
        
        logger.error("Error {}".format(e))
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        session = device.attach(pid)
    

    logger.info("Succesfully attacched frida to app")

    global file_log_frida

    dir_frida = os.path.join(file_log_frida, package_name.replace(".","_"))
    if not os.path.exists(dir_frida):
        os.makedirs(dir_frida)

    file_log_frida = os.path.join(dir_frida,  "monitoring_api_frida_{}.txt".format(package_name.replace(".", "_")))

    script_frida = create_script_frida(list_api_to_monitoring,
                                       os.path.join(os.getcwd(), "frida_scripts", "frida_script_template.js"))
    if store_script:
        file_script_frida = os.path.join(dir_frida,  "script_{}.js".format(package_name.replace(".", "_")))
        with open(file_script_frida, "w") as file:
            file.write(script_frida)
    
    script = session.create_script(script_frida.strip().replace("\n", ""))
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    start = time.time()
    while True:
        command = input("Press 0 to exit\n\nApi Invoked:\n")
        if command == "0":
            break

def get_cmd_args(args: list = None):
    """
        Parse and return the command line parameters needed for the script execution.
            :param args: List of arguments to be parsed (by default sys.argv is used).
            :return: The command line needed parameters.
    """

    parser = argparse.ArgumentParser(
        prog='python dynamic API monitoring based on Frida',
        description='Start dynamic API monitoring'
    )

    parser.add_argument('-f', '--file-apk', type=str, metavar='APK',
                        help='file apk to analyze')
    parser.add_argument('-p', '--package-name', type=str, metavar='PACKAGENAME',
                        help='Package Name of app to analyze')
    parser.add_argument('--list-api', type=str, metavar='API', nargs='+',
                        help='List of api file to monitoring, \ne.g., file_api.txt')
    parser.add_argument("--api", type=str, 
                        help="Single API to Monitoring, \ne.g., android.webkit.WebView,loadUrl")

    parser.add_argument("--store-script", type=bool, default=False)

    return parser.parse_args(args)


if __name__ == "__main__":
    
    arguments = get_cmd_args()
    if arguments.file_apk is not None:
        app_path = arguments.file_apk
        if os.path.exists(app_path):
            logger.info("Start Frida API Monitoring with App Installation")
            if arguments.list_api is not None:
                list_file_api_to_monitoring = arguments.list_api
                list_api_to_monitoring = create_list_api_from_file(list_file_api_to_monitoring)
                main(app_path, list_api_to_monitoring, app_to_install=True, store_script=arguments.store_script)
            elif arguments.api is not None:
                list_api_to_monitoring = []
                list_api_to_monitoring.append((arguments.api .split(",")[0], arguments.api.split(",")[1]))
                main(app_path, list_api_to_monitoring, app_to_install=True, store_script=arguments.store_script)
            else:
                arguments.print_help()
        else:
            print("File {} not found".format(app_path))
    elif arguments.package_name is not None:
        logger.info("Start Frida API Monitoring without App Installation")
        package_name = arguments.package_name
        if arguments.list_api is not None:
            list_file_api_to_monitoring = arguments.list_api
            list_api_to_monitoring = create_list_api_from_file(list_file_api_to_monitoring)
            main(package_name, list_api_to_monitoring, app_to_install=False, store_script=arguments.store_script)
        elif arguments.api is not None:
            list_api_to_monitoring = []
            list_api_to_monitoring.append((arguments.api .split(",")[0], arguments.api.split(",")[1]))
            main(package_name, list_api_to_monitoring, app_to_install=False, store_script=arguments.store_script)
        else:
            arguments.print_help()
        
    else:
        print("[*] Usage:  python frida_monitoring.py --file-apk app.apk --list-api api_personalized_1.txt api_personalized_2.txt")
        print("[*] Usage: python frida_monitoring.py --package-name com.example.analyticsapptesting --list-api api_personalized_1.txt api_personalized_2.txt")