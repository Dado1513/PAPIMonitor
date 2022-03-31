/******************************************************************************
 * Exported APIs
 1. loadclasses
 2. loadclasseswithfilter([filters])
 3. loadcustomfridascript(frida_script)
 4. loadmethods([loaded_classes])
 5. hookclassesandmethods([loaded_classes], [loaded_methods], template)
 6. generatehooktemplate([loaded_classes], [loaded_methods], template)
 ******************************************************************************/

rpc.exports = {

    loadclasses: function () {
        var loaded_classes = []

        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (className) {

                    //Remove too generics
                    if (className.length > 5)
                        loaded_classes.push(className)

                },
                onComplete: function () {
                    loaded_classes.sort()
                }
            });
        })
        return loaded_classes;
    },

    loadclasseswithfilter: function (filter) {
        var loaded_classes = []
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (className) {

                    //check if a filter exists
                    if (filter != null) {
                        //check if we have multiple filters (comma separated list)
                        var filter_array = filter.split(",");
                        filter_array.forEach(function (f) {
                            //f.trim() is needed to remove possibile spaces after the comma
                            if (className.startsWith(f.trim())) {
                                loaded_classes.push(className)
                            }
                        });
                    }
                },
                onComplete: function () {
                    loaded_classes.sort()
                }
            });
        })
        return loaded_classes;
    },

    loadcustomfridascript: function (frida_script) {
        Java.perform(function () {
            console.log("FRIDA script LOADED")
            eval(frida_script)
        })
    },

    loadmethods: function (loaded_classes) {
        var loaded_methods = {};
        Java.perform(function () {
            loaded_classes.forEach(function (className, index) {
                var jClass;
                var classMethods_dirty;

                //catch possible issues
                try{
                    jClass = Java.use(className);
                    classMethods_dirty = jClass.class.getDeclaredMethods();
                }catch(err){
                    send("Exception while loading methods for "+className);
                    //skip current loop
                    loaded_methods[className] = []
                    return;
                }
                var classMethods = []

                classMethods_dirty.forEach(function (m) {
                    var method_and_args = {};
                    //Cleaning up
                    m = m.toString();
                    //add info for the UI
                    method_and_args["ui_name"] = m.replace(className + ".", "")
                    // Remove generics from the method
                    while (m.includes("<")) {
                        m = m.replace(/<.*?>/g, "");
                    }
                    // remove "Throws"
                    if (m.indexOf(" throws ") !== -1) {
                        m = m.substring(0, m.indexOf(" throws "));
                    }
                    // remove scope and return type declarations
                    m = m.slice(m.lastIndexOf(" "));
                    // remove the class name
                    m = m.replace(className + ".", "");

                    // remove the signature (args)
                    method_and_args["name"] = m.split("(")[0].trim()

                    // get the args
                    var args_dirty = ((/\((.*?)\)/.exec(m)[1]).trim())

                    // add quotes between every arg
                    var args_array = args_dirty.split(",")
                    var args_srt = ""
                    for (var i = 0; i < args_array.length; i++) {
                        args_srt = args_srt + ("\"" + args_array[i] + "\"")
                        //add a comma if the current item is not the last one
                        if (i + 1 < args_array.length) args_srt = args_srt + ",";
                    }

                    method_and_args["args"] = args_srt
                    classMethods.push(method_and_args);

                });

                loaded_methods[className] = classMethods;
            });

        })
        //DEBUG console.log("loaded_classes.length: " + loaded_classes.length)
        //DEBUG console.log("loaded_methods.length: " + Object.keys(loaded_methods).length)
        return loaded_methods;
    },

    hookclassesandmethods: function (loaded_classes, loaded_methods, template) {

        Java.perform(function () {

            console.log("Hook Template setup")

            loaded_classes.forEach(function (clazz) {
                loaded_methods[clazz].forEach(function (dict) {
                    var t = template //template1

                    // replace className
                    t = t.replace("{className}", clazz);
                    // replace classMethod x3
                    t = t.replace("{classMethod}", dict["name"]);
                    t = t.replace("{classMethod}", dict["name"]);
                    t = t.replace("{classMethod}", dict["name"]);

                    //check if the method has args
                    if (dict["args"] != "\"\"") {
                        //check if the method has overloads
                        t = t.replace("{overload}", "overload(" + dict["args"] + ").");
                        // Check args length
                        var args_len = (dict["args"].split(",")).length

                        //args creation (method inputs) - v[i] to N
                        var args = "";
                        for (var i = 0; i < args_len; i++) {
                            if (i + 1 == args_len) args = args + "v" + i;
                            else args = args + "v" + i + ",";
                        }

                        //replace x2
                        t = t.replace("{args}", args);
                        t = t.replace("{args}", args);

                    } else {
                        //Current methods has NO args
                        // no need to overload
                        t = t.replace("{overload}", "overload().");
                        //replace x2 and no args
                        t = t.replace("{args}", "");
                        t = t.replace("{args}", "");
                    }

                    //Debug - print FRIDA template
                    //send(t);

                    // ready to eval!
                    eval(t);
                });
            });

        })
    },
    generatehooktemplate: function (loaded_classes, loaded_methods, template) {
        var hto = "" //hto stands for hooks template output
        Java.perform(function () {
            loaded_classes.forEach(function (clazz) {
                loaded_methods[clazz].forEach(function (dict) {
                    var t = template //template2

                    // replace className
                    t = t.replace("{className}", clazz);
                    // replace classMethod x3
                    t = t.replace("{classMethod}", dict["name"]);
                    t = t.replace("{classMethod}", dict["name"]);
                    t = t.replace("{classMethod}", dict["name"]);

                    t = t.replace("{methodSignature}", dict["ui_name"]);

                    //check if the method has args
                    if (dict["args"] != "\"\"") {
                        //check if the method has overloads
                        t = t.replace("{overload}", "overload(" + dict["args"] + ").");
                        // Check args length
                        var args_len = (dict["args"].split(",")).length

                        //args creation (method inputs) - v[i] to N
                        var args = "";
                        for (var i = 0; i < args_len; i++) {
                            if (i + 1 == args_len) args = args + "v" + i;
                            else args = args + "v" + i + ",";
                        }

                        //replace x3
                        t = t.replace("{args}", args);
                        t = t.replace("{args}", args);
                        t = t.replace("{args}", args);
                    } else {
                        //Current methods has NO args
                        // no need to overload
                        t = t.replace("{overload}", "overload().");
                        //replace x3
                        t = t.replace("{args}", "");
                        t = t.replace("{args}", "");
                        t = t.replace("{args}", "\"\"");
                    }

                    //Debug - print FRIDA template
                    //send(t);

                    // hooks concat
                    hto = hto + t;
                });
            });

        })
        // return HOOK template
        return hto;
    },
    heapsearchtemplate: function (loaded_classes, loaded_methods, template) {
        var hto = "" //hto stands for hooks template output
        Java.perform(function () {
            loaded_classes.forEach(function (clazz) {
                loaded_methods[clazz].forEach(function (dict) {
                    var t = template //template2

                    // replace className
                    t = t.replace("{className}", clazz);
                    // replace classMethod x2
                    t = t.replace("{classMethod}", dict["name"]);
                    t = t.replace("{classMethod}", dict["name"]);

                    t = t.replace("{methodSignature}", dict["ui_name"]);

                    //check if the method has args
                    if (dict["args"] != "\"\"") {

                        // Check args length
                        var args_len = (dict["args"].split(",")).length

                        //args creation (method inputs) - v[i] to N
                        var args = "";
                        for (var i = 0; i < args_len; i++) {
                            if (i + 1 == args_len) args = args + "v" + i;
                            else args = args + "v" + i + ",";
                        }

                        //replace
                        t = t.replace("{args}", args);

                    } else {
                        //Current methods has NO args

                        //replace
                        t = t.replace("{args}", "");

                    }

                    //Debug - print FRIDA template
                    //send(t);

                    // hooks concat
                    hto = hto + t;
                });
            });

        })
        // return HOOK template
        return hto;
    },
    apimonitor: function (api_to_monitor) {
        if (Java.available) {
            Java.perform(function () {
                api_to_monitor.forEach(function (e) {
                    e["hooks"].forEach(function (hook) {
                        // Java or Native Hook?
                        // Native - File System only at the moment
                        if (e["HookType"] == "Native") {
                            nativedynamichook(hook, e["Category"]);
                        }

                        // Java
                        if (e["HookType"] == "Java") {
                            javadynamichook(hook, e["Category"], function (realRetval, to_print) {
                                to_print.returnValue = realRetval
                                //check if type object if yes convert it to string
                                if (realRetval && typeof realRetval === 'object') {
                                    var retval_string = [];
                                    for (var k = 0, l = realRetval.length; k < l; k++) {
                                        retval_string.push(realRetval[k]);
                                    }
                                    to_print.returnValue = '' + retval_string.join('');
                                }
                                if (!to_print.result) to_print.result = undefined
                                if (!to_print.returnValue) to_print.returnValue = undefined
                                send(JSON.stringify(to_print));
                                return realRetval;
                            });
                        } // end javadynamichook
                    });

                });

            })
        }
    }
};

function nativedynamichook(hook, category) {
    // File System monitor only - libc.so
    Interceptor.attach(
        Module.findExportByName(hook["clazz"], hook["method"]), {
            onEnter: function (args) {
                var file = Memory.readCString(args[0]);
                //bypass ashem and prod if libc.so - open
                if (hook["clazz"] == "libc.so" &&
                    hook["method"] == "open" &&
                    !file.includes("/dev/ashmem") &&
                    !file.includes("/proc/"))
                    send("API Monitor - " + category + " - " + hook["clazz"] + " - " + hook["method"] + " - " + file);
            }
        }
    );
}


function javadynamichook(hook, category, callback) {

    // console.log(hook.clazz);
    // console.log(hook.method);
    /*
    var classFactory;
    const classLoaders = Java.enumerateClassLoadersSync();
    for (var i=0; i< classLoaders.length; i++) {
      try {
        // console.log(classLoaders[classLoader]);
        classLoaders[classLoaders[i]].findClass(hook.clazz);
        classFactory = Java.ClassFactory.get(classLoaders[i]);
        break;
      } catch (e) {
        continue;
      }
    }
    */
    // enumerateClassLoaded();
    var Exception = Java.use('java.lang.Exception');
    var toHook;
    try {
        var clazz = hook.clazz;
        var method = hook.method;
        try {
            if (hook.target &&
                parseInt(Java.androidVersion, 10) < hook.target) {
                console.log('[API Monitor] - Android Version not supported - Cannot hook - ' + clazz + '.' + method);
                return
            }

            // Check if class and method is available
            // console.log(JSON.stringify(classFactory))

            try {
                console.log(clazz)
                var clazzJava =  Java.use(clazz);
                // var clazzJava = Java.registerClass({"name": clazz})
                console.log(method)
                toHook = clazzJava[method];
                // toHook = classFactory.use(clazz)[method];
                // console.log(clazz)

                // console.log(Object.getOwnPropertyNames(clazzJava.__proto__).join('\n'))
                /*
                var methods = clazzJava.class.getDeclaredMethods();
                if (Object.getOwnPropertyNames(clazzJava).includes(hook.method)) {
                  console.log("method: "+hook.method);
                  console.log("clazz:" + clazz);
                  console.log(Object.getOwnPropertyNames(clazzJava))
                  // clazzJava
                  try {
                    toHook = clazzJava[hook.method];
                    // console.log(toHook);
                  }catch (e) {
                    console.log(e)
                    toHook = undefined
                  }
                }
                */
                // for (var m in methods){
                // console.log("methods: " + methods[m]);
                // console.log("m: "+methods[m].toString());
                // var methodName = methods[m].toString().split("(")[0].split(".").pop()

                // clazzJava.$dispose;
                // console.log(JSON.stringify(clazzJava.class[methodName]));
                // console.log(method_name)
                // console.log(JSON.stringify(clazzJava[m]))
                // console.log()
                // }
                // var clazzJava = classFactory.use(clazz)

                // console.log(clazz)
                // var clazzJava = Java.registerClass({"name": clazz})
                // console.log(clazzJava.class.getMethods())
                // console.log(method)
                // console.log(clazzJava.class.getMethods())

                // if (method != null && method != "null") {
                // console.log("clazzJava: "+ clazzJava)
                // console.log("before: "+ method);
                // console.log("after: "+ method);
                // }

                // console.log(toHook + "FOUND")

            } catch (e){

                console.log("Not found")
                toHook = false;
            }
            if (!toHook) {
                console.log('[API Monitor] - Cannot find ' + clazz + '.' + method);
                return
            }
        } catch (err) {
            console.log('[API Monitor] - Cannot find ' + clazz + '.' + method);
            return
        }
        for (var i = 0; i < toHook.overloads.length; i++) {
            console.log("Hooked: "+toHook.overloads[i])
            toHook.overloads[i].implementation = function () {
                var args = [].slice.call(arguments);
                // Call original method
                var retval = this[method].apply(this, arguments);
                if (callback) {
                    var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
                    var to_print = {
                        category: category,
                        class: clazz,
                        method: method,
                        args: args,
                        calledFrom: calledFrom,
                        result: retval ? retval.toString() : "N/A",
                    };
                    retval = callback(retval, to_print);
                }
                return retval;
            }
        }
    } catch (err) {
        console.log('[API Monitor] - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
    }
}


function enumerateClassLoaded(){
    var classes = Java.enumerateLoadedClassesSync();
    classes = classes.sort();
    for(var i=0; i < classes.length; i++ ) {
        try {
            // console.log(classes[i]);
            // send("[API Monitor] Class Found "+ JSON.stringify(classes[i]));
            var clazz = Java.use(classes[i]);
            // send("API Monitor" + classes[i] + " Found")
            var methods = clazz.class.getMethods();
            for (var i = 0; i < methods.length; i++) {
                send("[API Monitor] class: "+ classes[i] + " method: " + methods[i].toString())
            }
        } catch (e){
            continue
            // console.log(classes[i] + " Not Found")
        }
    }
}