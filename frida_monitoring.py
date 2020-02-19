import frida
import os
import logging
import sys
from androguard.misc import AnalyzeAPK
import time

from adb import ADB

if 'LOG_LEVEL' in os.environ:
    log_level = os.environ['LOG_LEVEL']
else:
    log_level = logging.INFO

LOCAL_URL_EMULATOR = "http://127.0.0.1:21212"
logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s> [%(levelname)s][%(name)s][%(funcName)s()] %(message)s',
                        datefmt='%d/%m/%Y %H:%M:%S', level=log_level)


def on_message(message, data):
    if message['type'] == 'send':
        print(message["payload"])
        # logging.info(message['payload'])
    elif message['type'] == 'error':
        print(message["stack"])
        # logging.info(message['stack'])


def push_and_start_frida_server(adb: ADB):
    """

    Parameters
    ----------
    adb

    Returns
    -------

    """
    frida_server = os.path.join(os.getcwd(), "resources", "frida-server", "frida-server")
    adb.execute(['root'])
    logger.info("Push frida server")
    adb.push_file(frida_server, "/data/local/tmp")
    logger.info("Add execution permission to frida-server")
    chmod_frida = ["chmod 755 /data/local/tmp/frida-server"]
    adb.shell(chmod_frida)
    logger.info("Start frida server")
    start_frida = ["./data/local/tmp/frida-server &"]
    adb.shell(start_frida)


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

def main():
    # app already installed and frida already running on device
    package_name = sys.argv[1]
    execution_time = int(sys.argv[2])
    file_api_to_monitoring = sys.argv[3]
    list_api_to_monitoring = read_api_to_monitoring(file_api_to_monitoring)
    print(list_api_to_monitoring)


    pid = None
    device = None
    session = None
    try:
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        session = device.attach(pid)
    except Exception as e:
        logger.error("Error {}".format(e))

    logger.info("Succesfully attacched frida to app")
    with open(os.path.join(os.getcwd(), "frida_scripts", "frida_script_template.js")) as frida_script_file:
        script_frida_template = frida_script_file.read()

    script_frida = ""
    for tuple_class_method in list_api_to_monitoring:
        script_frida += script_frida_template.replace("class_name", "\""+tuple_class_method[0]+"\"").\
        replace("method_name", "\""+tuple_class_method[1]+"\"") + "\n\n"
    print(script_frida)


    script = session.create_script(script_frida.strip().replace("\n",""))
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    start = time.time()
    while True:
        end = time.time()
        if int(end - start) > execution_time:
            session.detach()
            break


if __name__ == "__main__":
    if len(sys.argv) == 4:
        main()
    else:
        print("[*] Usage: python frida_monitoring.py com.example.app 5000 api.txt")