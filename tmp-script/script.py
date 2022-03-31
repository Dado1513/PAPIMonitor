import frida
import time

def on_message(message, data):
    print(message)
    print(data)



device = frida.get_usb_device()
pid = device.spawn(["com.example.testandroid"])
device.resume(pid)
time.sleep(2) #Without it Java.perform silently fails
process = device.attach(pid)

with open("script.js") as f:
    script = process.create_script(f.read())
script.on("message", on_message)
script.load()
while True:
    command = input("Press 0 to exit\n\n")
    if command == "0":
        break
