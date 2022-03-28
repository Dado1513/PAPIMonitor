import frida
from datetime import datetime
import argparse
from rich import print
from rich.console import Console
from utils import *
from loguru import logger

console = Console()
file_log_frida = os.path.join(os.path.dirname(__file__), "logs")


def on_message(message, data):
    """

    Parameters
    ----------
    message
    data

    Returns
    -------

    """
    file_log = open(file_log_frida, "a")
    if message["type"] == "send":
        if type(message["payload"]) is str:
            if "API Monitor" not in message["payload"]:
                message_dict = json.loads(message["payload"])
            else:
                file_log.write(str(message["payload"]) + "\n")
                try:
                    console.log(json.loads(message["payload"]))
                except json.decoder.JSONDecodeError as e:
                    pass
                return
        else:
            message_dict = message["payload"]
        if "Error" not in str(message_dict):
            message_dict["time"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            file_log.write(str(message_dict) + "\n")
            try:
                console.log(json.loads(message["payload"]))
            except json.decoder.JSONDecodeError as e:
                pass
    file_log.close()


def main(
    app_path: str,
    api_monitor_file : str = None,
    is_app_to_install: bool = True,
    is_google_emulator: bool = False,
    category: list = ["NONE"],
):
    """

    Parameters
    ----------
    app_path
    api_monitor_file
    is_app_to_install
    is_google_emulator
    category

    Returns
    -------

    """
    if is_app_to_install:
        package_name = install_app_and_install_frida(app_path=app_path, is_google_emulator=is_google_emulator)
    else:
        package_name = create_adb_and_start_frida(package_name=app_path, is_google_emulator=is_google_emulator)

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

    logger.debug("Succesfully attacched frida to app")

    global file_log_frida
    dir_frida = os.path.join(file_log_frida, package_name.replace(".", "_"))
    if not os.path.exists(dir_frida):
        os.makedirs(dir_frida)

    file_log_frida = os.path.join(
        dir_frida, "monitoring_api_frida_{}.txt".format(package_name.replace(".", "_"))
    )

    with open(
        os.path.join(os.path.dirname(__file__), "api_android_monitor", "default.js")
    ) as f:
        frida_code = f.read()

    script = session.create_script(frida_code)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    api = script.exports
    api_monitor = []

    if api_monitor_file is not None:
        json_api_monitor = create_json_api_monitor(api_monitor_file)
        if json_api_monitor is not None:
            api_monitor.append(json_api_monitor)
            # append all category
            for e in json_api_monitor:
                category.append(e["Category"])
    if "NONE" not in category:
        # add api_monitor default
        with open(
            os.path.join(
                os.path.dirname(__file__), "api_android_monitor", "api_monitor.json"
            )
        ) as f:
            api_monitor = api_monitor + json.load(f)

        # remove app filtered
        if "ALL" not in category:
            api_filter = [e for e in api_monitor if e["Category"] in category]
            api_to_hook = json.loads(json.dumps(api_filter))
            # logger.info(api_to_hook)
            api.apimonitor(api_to_hook)
        else:
            api.apimonitor(api_monitor)
    else:
        api.apimonitor(api_monitor)

    while True:
        command = input("Press 0 to exit\n\n")
        if command == "0":
            break


def get_cmd_args(args: list = None):
    """
    Parse and return the command line parameters needed for the script execution.
        :param args: List of arguments to be parsed (by default sys.argv is used).
        :return: The command line needed parameters.
    """

    parser = argparse.ArgumentParser(
        prog="Python API Monitor for Android apps",
        description="Start dynamic API monitoring",
        usage="""
            python papi_monitor.py --package-name com.package.name --filter "Crypto"
            python papi_monitor.py --file-apk app.apk --api-monitor api_personalized_1.txt
            python papi_monitor.py --package-name com.package.name --api-monitor api_personalized_1.txt
            python papi_monitor.py --package-name com.package.name --filter "ALL"
            python papi_monitor.py --package-name com.package.name --list-api api_personalized.txt --store-script True --filter "Crypto" "Crypto - Hash"

        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-f", "--file-apk", type=str, metavar="APK", help="file apk to analyze"
    )

    parser.add_argument(
        "-p",
        "--package-name",
        type=str,
        metavar="PACKAGENAME",
        help="Package Name of app to analyze",
    )
    parser.add_argument(
        "--api-monitor",
        type=str,
        metavar="API",
        help="File that contain the list of API to monitoring, \ne.g., hooks.json",
    )

    parser.add_argument(
        "--filter",
        type=str,
        nargs="+",
        choices=[
            "Device Data",
            "Device Info",
            "SMS",
            "System Manager",
            "Base64 encode/decode",
            "Dex Class Loader",
            "Network",
            "Crypto",
            "Crypto - Hash",
            "Binder",
            "IPC",
            "Database",
            "SharedPreferences",
            "WebView",
            "Java Native Interface",
            "Command",
            "Process",
            "FileSystem - Java",
            "ALL",
            "NONE",
        ],
        default=["NONE"],
    )
    parser.add_argument("--store-script", type=bool, default=False)
    parser.add_argument("--google-emulator", action="store_true")
    return parser.parse_args(args)


if __name__ == "__main__":

    arguments = get_cmd_args()
    app = None
    is_app_to_install = False

    if arguments.file_apk is not None and os.path.exists(arguments.file_apk):
        logger.info("Start PAPIMonitor with App Installation")
        app = arguments.file_apk
        is_app_to_install = True
    elif arguments.package_name is not None:
        logger.info("Start PAPIMonitor without App Installation")
        app = arguments.package_name
        is_app_to_install = False

    if app is not None:

        # if app is not None mean that the app path exist or package name is set
        if arguments.api_monitor is not None:
            # argument is a file of API to monitor hook.txt/json
            monitor_file = arguments.api_monitor
            main(
                app,
                api_monitor_file=arguments.api_monitor,
                is_app_to_install=is_app_to_install,
                category=arguments.filter,
            )

        else:
            # used list api of chosen by user (default is NONE)
            main(
                app,
                None,
                is_app_to_install=is_app_to_install,
                category=arguments.filter,
            )

    else:
        print(
            "[bold][*] Usage: python papi_monitor.py --package-name com.package.name[/bold]"
        )
        print(
            "[bold][*] Usage: python papi_monitor.py --file-apk app.apk --list-api api_personalized_1.txt [/bold]"
        )
        print(
            "[bold][*] Usage: python papi_monitor.py --package-name com.package.name "
            "--api-monitor api_personalized_1.txt [/bold]"
        )
        print(
            "[bold][*] Usage: python papi_monitor.py --package-name ccom.package.name --filter \"Crypto\" [/bold]"
        )
