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
        if type(message["payload"]) is str:
            if "API Monitor" not in message["payload"]:
                message_dict = json.loads(message["payload"])
            else:
                file_log.write(str(message["payload"]) + "\n")
                logger.info(str(message["payload"])+"\n")
                return 
        else:
            message_dict = message["payload"]
        if "Error" not in str(message_dict):
            message_dict["time"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            file_log.write(str(message_dict) + "\n")
            logger.info(str(message_dict)+"\n")
    file_log.close()


def on_message_api_monitor(message, data):
    file_log = open(file_log_frida, "a")
    if message['type'] == 'send':
        print(type(message["payload"]))
        file_log.write(str(message["payload"]) + "\n")
        logger.info(message["payload"])
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
    time.sleep(4)


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


def create_json_custom(list_api_to_monitoring):
    dict_category_custom =  {
            "Category": "Custom",
            "HookType": "Java",
            "hooks": []
    }
    
    for api in list_api_to_monitoring:
        dict_method = {
            "clazz": api[0],
            "method": api[1]
        }
        dict_category_custom["hooks"].append(dict_method)
    
    return dict_category_custom
    


def main_v2(app_path, list_api_to_monitoring=None, app_to_install=True, store_script=False, category=["ALL"]):
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

    with open(os.path.join(os.getcwd(), "frida_script_v2", "default.js")) as f:
        frida_code = f.read()
    
    script = session.create_script(frida_code)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    api = script.exports
    
    
    with open(os.path.join(os.getcwd(), "frida_script_v2","api_monitor.json")) as f:
        api_monitor = json.load(f)
    
    if list_api_to_monitoring is not None:
        json_custom = create_json_custom(list_api_to_monitoring)
        api_monitor.append(json_custom)
        category.append("Custom")
    
    if "ALL" not in category:
        api_filter = [e for e in api_monitor if e['Category'] in category] 
        api_to_hook = json.loads(json.dumps(api_filter))
        api.apimonitor(api_to_hook)
    else:
        api.apimonitor(api_monitor)
    

    
    while True:
        command = input("Press 0 to exit\n\nApi Invoked:\n")
        if command == "0":
            break


def main_v1(app_path, list_api_to_monitoring, app_to_install=True, store_script=False):
        
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
        description='Start dynamic API monitoring',
        usage="""
            python frida_monitoring.py -v 1 --file-apk app.apk --list-api api_personalized_1.txt api_personalized_2.txt
            python frida_monitoring.py -v 1 --package-name com.example.analyticsapptesting --list-api api_personalized_1.txt api_personalized_2.txt
            python frida_monitoring.py -v 2 --package-name com.example.analyticsapptesting
            python frida_monitoring.py -v 2 --file-apk app.apk --list-api api_personalized_1.txt api_personalized_2.txt
            python frida_monitoring.py -v 2 --package-name com.example.analyticsapptesting --list-api api_personalized_1.txt api_personalized_2.txt
            python frida_monitoring.py -v 2 --package-name com.example.analyticsapptesting
            python frida_monitoring.py -v 2 --package-name com.example.app --list-api api_personalized.txt api_personalized_2.txt --store-script True --filter "Crypto" "Crypto - Hash"

        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-f', '--file-apk', type=str, metavar='APK',
                        help='file apk to analyze')
    
    parser.add_argument('-v', '--version', type=str, metavar='VERSION', choices=["1","2"], required=True,
                        help="Version API Monitoring,\n -v 1 => Original,\n -v 2 => Based on https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security")
    
    parser.add_argument('-p', '--package-name', type=str, metavar='PACKAGENAME',
                        help='Package Name of app to analyze')
    parser.add_argument('--list-api', type=str, metavar='API', nargs='+',
                        help='List of api file to monitoring, \ne.g., file_api.txt')
    parser.add_argument("--api", type=str, 
                        help="Single API to Monitoring, \ne.g., android.webkit.WebView,loadUrl")
    parser.add_argument('--filter', type=str, nargs="+", choices=["Device Data", "Device Info", "SMS", "System Manager", 
                                                                    "Base64 encode/decode", "Dex Class Loader","Network", 
                                                                    "Crypto", "Crypto - Hash", "Binder", "IPC", "Database", "SharedPreferences", "WebView",
                                                                    "Java Native Interface", "Command", "Process", "FileSytem - Java", "ALL"], default=["ALL"])
    parser.add_argument("--store-script", type=bool, default=False)

    return parser.parse_args(args)


if __name__ == "__main__":
    

    arguments = get_cmd_args()
    print(arguments.filter)
    if arguments.version == "1":
        if arguments.file_apk is not None:
            app_path = arguments.file_apk
            if os.path.exists(app_path):
                logger.info("Start Frida API Monitoring with App Installation")
                
                if arguments.list_api is not None:
                    list_file_api_to_monitoring = arguments.list_api
                    list_api_to_monitoring = create_list_api_from_file(list_file_api_to_monitoring)
                    main_v1(app_path, list_api_to_monitoring, app_to_install=True, store_script=arguments.store_script)
                
                elif arguments.api is not None:
                    list_api_to_monitoring = []
                    list_api_to_monitoring.append((arguments.api .split(",")[0], arguments.api.split(",")[1]))
                    main_v1(app_path, list_api_to_monitoring, app_to_install=True, store_script=arguments.store_script)
                
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
                main_v1(package_name, list_api_to_monitoring, app_to_install=False, store_script=arguments.store_script)
            elif arguments.api is not None:
                list_api_to_monitoring = []
                list_api_to_monitoring.append((arguments.api .split(",")[0], arguments.api.split(",")[1]))
                main_v1(package_name, list_api_to_monitoring, app_to_install=False, store_script=arguments.store_script)
            else:
                arguments.print_help()
    
    elif arguments.version == "2":
        if arguments.file_apk is not None:
            app_path = arguments.file_apk
            if os.path.exists(app_path):
                logger.info("Start Frida API Monitoring with App Installation")

                if arguments.list_api is not None:
                    list_file_api_to_monitoring = arguments.list_api
                    list_api_to_monitoring = create_list_api_from_file(list_file_api_to_monitoring)
                    main_v2(app_path, list_api_to_monitoring, app_to_install=True, store_script=arguments.store_script, category=arguments.filter)
                elif arguments.api is not None:
                    list_api_to_monitoring = []
                    list_api_to_monitoring.append((arguments.api .split(",")[0], arguments.api.split(",")[1]))
                    main_v2(app_path, list_api_to_monitoring, app_to_install=True, store_script=arguments.store_script, category=arguments.filter)
                else:
                    main_v2(app_path, None, app_to_install=True, store_script=arguments.store_script, category=arguments.filter)
            else:
                print("File {} not found".format(app_path))
        
        elif arguments.package_name is not None:
            logger.info("Start Frida API Monitoring without App Installation")
            package_name = arguments.package_name
            if arguments.list_api is not None:
                list_file_api_to_monitoring = arguments.list_api
                list_api_to_monitoring = create_list_api_from_file(list_file_api_to_monitoring)
                main_v2(package_name, list_api_to_monitoring, app_to_install=False, store_script=arguments.store_script, category=arguments.filter)
                
            elif arguments.api is not None:
                list_api_to_monitoring = []
                list_api_to_monitoring.append((arguments.api .split(",")[0], arguments.api.split(",")[1]))
                main_v2(package_name, list_api_to_monitoring, app_to_install=False, store_script=arguments.store_script, category=arguments.filter)

            else:
                main_v2(package_name, list_api_to_monitoring, app_to_install=False, store_script=arguments.store_script, category=arguments.filter)
    else:
        print("[*] Usage: python frida_monitoring.py -v 1 --file-apk app.apk --list-api api_personalized_1.txt api_personalized_2.txt")
        print("[*] Usage: python frida_monitoring.py -v 1 --package-name com.example.analyticsapptesting --list-api api_personalized_1.txt api_personalized_2.txt")
        print("[*] Usage: python frida_monitoring.py -v 2 --package-name com.example.analyticsapptesting")
        print("[*] Usage: python frida_monitoring.py -v 2 --file-apk app.apk --list-api api_personalized_1.txt api_personalized_2.txt")
        print("[*] Usage: python frida_monitoring.py -v 2 --package-name com.example.analyticsapptesting --list-api api_personalized_1.txt api_personalized_2.txt")
        print("[*] Usage: python frida_monitoring.py -v 2 --package-name com.example.analyticsapptesting")

        