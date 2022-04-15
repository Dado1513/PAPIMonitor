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
            console.log("[*] Exception while loading methods for "+className);
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
      Java.perform(function () {
        console.log("[*] api-monitor")
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
    },

    pinningbypass: function() {
      setTimeout(function(){
        Java.perform(function (){
          console.log("");
          console.log("[.][pinning-bypass] Cert Pinning Bypass/Re-Pinning");
    
          var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
          var FileInputStream = Java.use("java.io.FileInputStream");
          var BufferedInputStream = Java.use("java.io.BufferedInputStream");
          var X509Certificate = Java.use("java.security.cert.X509Certificate");
          var KeyStore = Java.use("java.security.KeyStore");
          var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
          var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
          // Load CAs from an InputStream
          console.log("[+][pinning-bypass] Loading our CA...")
          var cf = CertificateFactory.getInstance("X.509");
          
          try {
            var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
          }
          catch(err) {
            console.log("[o][pinning-bypass] " + err);
          }
          
          var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
          var ca = cf.generateCertificate(bufferedInputStream);
          bufferedInputStream.close();
    
          var certInfo = Java.cast(ca, X509Certificate);
          console.log("[o][pinning-bypass] Our CA Info: " + certInfo.getSubjectDN());
    
          // Create a KeyStore containing our trusted CAs
          console.log("[+][pinning-bypass] Creating a KeyStore for our CA...");
          var keyStoreType = KeyStore.getDefaultType();
          var keyStore = KeyStore.getInstance(keyStoreType);
          keyStore.load(null, null);
          keyStore.setCertificateEntry("ca", ca);
          
          // Create a TrustManager that trusts the CAs in our KeyStore
          console.log("[+][pinning-bypass] Creating a TrustManager that trusts the CA in our KeyStore...");
          var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
          var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
          tmf.init(keyStore);
          console.log("[+][pinning-bypass] Our TrustManager is ready...");
    
          console.log("[+][pinning-bypass] Hijacking SSLContext methods now...")
          console.log("[-][pinning-bypass] Waiting for the app to invoke SSLContext.init()...")
    
          SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
            console.log("[o][pinning-bypass] App invoked javax.net.ssl.SSLContext.init...");
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
            console.log("[+][pinning-bypass] SSLContext initialized with our custom TrustManager!");
          }

          // okhttp3 pinning
          var okhttp3_CertificatePinner_class = null;
          try {
                  okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');    
              } catch (err) {
                  console.log('[-][pinning-bypass] OkHTTPv3 CertificatePinner class not found. Skipping.');
                  okhttp3_CertificatePinner_class = null;
              }
      
              if(okhttp3_CertificatePinner_class != null) {
      
                try{
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str,list) {
                        console.log('[+][pinning-bypass] Bypassing OkHTTPv3 1: ' + str);
                        return true;
                    };
                    console.log('[+][pinning-bypass] Loaded OkHTTPv3 hook 1');
                } catch(err) {
                  console.log('[-][pinning-bypass] Skipping OkHTTPv3 hook 1');
                }
      
                try{
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str,cert) {
                        console.log('[+][pinning-bypass] Bypassing OkHTTPv3 2: ' + str);
                        return true;
                    };
                    console.log('[+][pinning-bypass] Loaded OkHTTPv3 hook 2');
                } catch(err) {
                  console.log('[-][pinning-bypass] Skipping OkHTTPv3 hook 2');
                }
      
                try {
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str,cert_array) {
                        console.log('[+][pinning-bypass] Bypassing OkHTTPv3 3: ' + str);
                        return true;
                    };
                    console.log('[+][pinning-bypass] Loaded OkHTTPv3 hook 3');
                } catch(err) {
                  console.log('[-][pinning-bypass] Skipping OkHTTPv3 hook 3');
                }
      
                try {
                    okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str,obj) {
                      console.log('[+][pinning-bypass] Bypassing OkHTTPv3 4 (4.2+): ' + str);
                  };
                  console.log('[+][pinning-bypass] Loaded OkHTTPv3 hook 4 (4.2+)');
              } catch(err) {
                  console.log('[-][pinning-bypass] Skipping OkHTTPv3 hook 4 (4.2+)');
                }
      
          }
      
        });
      },0);
    },

    jailmonkeybypass: function(){
      Java.perform(() => {
        const klass = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
        const hashmap_klass = Java.use("java.util.HashMap");
        const false_obj = Java.use("java.lang.Boolean").FALSE.value;
    
        klass.getConstants.implementation = function () {
            var h = hashmap_klass.$new();
            h.put("isJailBroken", false_obj);
            h.put("hookDetected", false_obj);
            h.put("canMockLocation", false_obj);
            h.put("isOnExternalStorage", false_obj);
            h.put("AdbEnabled", false_obj);
            return h;
        };
      });
    },

    antirootbypass: function(){
      // CHANGELOG by Pichaya Morimoto (p.morimoto@sth.sh): 
      //  - I added extra whitelisted items to deal with the latest versions 
      // 						of RootBeer/Cordova iRoot as of August 6, 2019
      //  - The original one just fucked up (kill itself) if Magisk is installed lol
      // Credit & Originally written by: https://codeshare.frida.re/@dzonerzy/fridantiroot/
      // If this isn't working in the future, check console logs, rootbeer src, or libtool-checker.so
      Java.perform(function() {

        var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
            "eu.chainfire.supersu.pro", "com.kingouser.com", "com.android.vending.billing.InAppBillingService.COIN","com.topjohnwu.magisk"
        ];

        var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk","magisk", "/system/xbin/su"];

        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1"
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        var Runtime = Java.use('java.lang.Runtime');
        var NativeFile = Java.use('java.io.File');
        var String = Java.use('java.lang.String');
        var SystemProperties = Java.use('android.os.SystemProperties');
        var BufferedReader = Java.use('java.io.BufferedReader');
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        var StringBuffer = Java.use('java.lang.StringBuffer');
        var loaded_classes = Java.enumerateLoadedClassesSync();

        console.log("[*][antiroot-bypass] Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        console.log("[*][antiroot-bypass] loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

        if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
            try {
                //useProcessManager = true;
                //var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
              console.log("[*][antiroot-bypass] ProcessManager Hook failed: " + err);
            }
        } else {
          console.log("[*][antiroot-bypass] ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
            try {
                //useKeyInfo = true;
                //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
              console.log("[*][antiroot-bypass] KeyInfo Hook failed: " + err);
            }
        } else {
          console.log("[*][antiroot-bypass] KeyInfo hook not loaded");
        }

        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
            var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
            if (shouldFakePackage) {
              console.log("[*][antiroot-bypass] Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo.call(this, pname, flags);
        };

        NativeFile.exists.implementation = function() {
          var name = NativeFile.getName.call(this);
          var shouldFakeReturn = RootBinaries.find(element => {
            if (element.includes(name))
                return true;
          });
          // var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
          if (shouldFakeReturn) {
                console.log("[*][antiroot-bypass] Bypass return value for binary: " + name);
                return false;
          } else {
              return this.exists.call();
          }
        };

        var exec = Runtime.exec.overload('[Ljava.lang.String;');
        var exec1 = Runtime.exec.overload('java.lang.String');
        var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
        var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
        var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
        var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

        exec5.implementation = function(cmd, env, dir) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                console.log("[*][antiroot-bypass] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                console.log("[*][antiroot-bypass] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "which") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                console.log("[*][antiroot-bypass] Bypass which command");
                return exec1.call(this, fakeCmd);
            }
            return exec5.call(this, cmd, env, dir);
        };

        exec4.implementation = function(cmdarr, env, file) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    console.log("[*][antiroot-bypass] Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    console.log("[*][antiroot-bypass] Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec4.call(this, cmdarr, env, file);
        };

        exec3.implementation = function(cmdarr, envp) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    console.log(" [*][antiroot-bypass] Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    console.log(" [*][antiroot-bypass] Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec3.call(this, cmdarr, envp);
        };

        exec2.implementation = function(cmd, env) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                console.log(" [*][antiroot-bypass] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                console.log(" [*][antiroot-bypass] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec2.call(this, cmd, env);
        };

        exec.implementation = function(cmd) {
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    console.log(" [*][antiroot-bypass] Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    console.log(" [*][antiroot-bypass] Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
            }

            return exec.call(this, cmd);
        };

        exec1.implementation = function(cmd) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                console.log(" [*][antiroot-bypass] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                console.log(" [*][antiroot-bypass] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec1.call(this, cmd);
        };

        String.contains.implementation = function(name) {
            if (name == "test-keys") {
                console.log(" [*][antiroot-bypass] Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload('java.lang.String');

        get.implementation = function(name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                console.log(" [*][antiroot-bypass] Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function(args) {
                var path1 = Memory.readCString(args[0]);
                var path = path1.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/ggezxxx");
                    console.log(" [*][antiroot-bypass] Bypass native fopen >> "+path1);
                }
            },
            onLeave: function(retval) {

            }
        });

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function(args) {
                var path1 = Memory.readCString(args[0]);
                var path = path1.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/ggezxxx");
                    console.log(" [*][antiroot-bypass] Bypass native fopen >> "+path1);
                }
            },
            onLeave: function(retval) {

            }
        });

        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function(args) {
                var cmd = Memory.readCString(args[0]);
                console.log(" [*][antiroot-bypass] SYSTEM CMD: " + cmd);
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                    console.log(" [*][antiroot-bypass] Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    console.log(" [*][antiroot-bypass] Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                }
            },
            onLeave: function(retval) {

            }
        });

        /*

        TO IMPLEMENT:

        Exec Family

        int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
        int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
        int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execv(const char *path, char *const argv[]);
        int execve(const char *path, char *const argv[], char *const envp[]);
        int execvp(const char *file, char *const argv[]);
        int execvpe(const char *file, char *const argv[], char *const envp[]);

        */


        BufferedReader.readLine.overload().implementation = function() {
            var text = this.readLine.call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                if (shouldFakeRead) {
                    console.log(" [*][antiroot-bypass] Bypass build.prop file read");
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }
            }
            return text;
        };

        var executeCommand = ProcessBuilder.command.overload('java.util.List');

        ProcessBuilder.start.implementation = function() {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                console.log(" [*][antiroot-bypass] Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                console.log(" [*][antiroot-bypass] Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
            var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

            ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        console.log(" [*][antiroot-bypass] Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        console.log(" [*][antiroot-bypass] Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        console.log(" [*][antiroot-bypass] Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        console.log(" [*][antiroot-bypass] Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function() {
                console.log(" [*][antiroot-bypass] Bypass isInsideSecureHardware");
                return true;
            }
        }
    });

    },

    rootbeerbypass: function(){

      setTimeout(function(){
        Java.perform(function (){

          console.log("[*] root beer bypass")
          var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
          "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
          "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
          "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
          "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
          "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
          "eu.chainfire.supersu.pro", "com.kingouser.com", "com.android.vending.billing.InAppBillingService.COIN","com.topjohnwu.magisk"
          ];

          var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk","magisk"];

          var RootProperties = {
              "ro.build.selinux": "1",
              "ro.debuggable": "0",
              "service.adb.root": "0",
              "ro.secure": "1"
          };

          var RootPropertiesKeys = [];

          for (var k in RootProperties) RootPropertiesKeys.push(k);

          var PackageManager = Java.use("android.app.ApplicationPackageManager");
          var Runtime = Java.use('java.lang.Runtime');
          var NativeFile = Java.use('java.io.File');

          NativeFile.exists.implementation = function() {
            var name = NativeFile.getAbsolutePath.call(this);
            console.log(name);
            var shouldFakeReturn = RootBinaries.find(element => {
              if (name.includes(element))
                return true;
            });
            
            if (shouldFakeReturn) {
              console.log("[*][antiroot-bypass] Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
          };

        });
      }, 0);

    },

    antifridabypass: function(){
      Java.perform(() => { 
        Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

          onEnter: function(args) {
      
              this.haystack = args[0];
              this.needle = args[1];
              this.frida = Boolean(0);
      
              haystack = Memory.readUtf8String(this.haystack);
              needle = Memory.readUtf8String(this.needle);
      
              if (haystack.indexOf("frida") !== -1 || haystack.indexOf("xposed") !== -1) {
                  this.frida = Boolean(1);
              }
          },
      
          onLeave: function(retval) {
      
              if (this.frida) {
                  retval.replace(0);
              }
              return retval;
          }
        });
      });
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
            console.log("[API Monitor] - " + category + " - " + hook["clazz"] + " - " + hook["method"] + " - " + file);
        }
      }
    );
  }
  
  function javadynamichook(hook, category, callback) {
    var Exception = Java.use('java.lang.Exception');
    var toHook;
    try {
      var clazz = hook.clazz;
      var method = hook.method;
  
      try {
        if (hook.target &&
          parseInt(Java.androidVersion, 10) < hook.target) {
          send('API Monitor - Android Version not supported - Cannot hook - ' + clazz + '.' + method)
          return
        }
        // Check if class and method is available
        toHook = Java.use(clazz)[method];
        if (!toHook) {
          send('API Monitor - Cannot find ' + clazz + '.' + method);
          return
        }
      } catch (err) {
        send('API Monitor - Cannot find ' + clazz + '.' + method);
        return
      }
      
      // if contains only one methods


      if (toHook.overloads == undefined){
          toHook.implementation =  function () {
            if (arguments !== undefined) {
              var args = [].slice.call(arguments);
              
              if (args !== undefined){
                for (var k = 0, l = args.length; k < l; k++) {
                  args_string_value.push(args[k] + "");
                }
              }
            }
            
            // Call original method
            var retval = this[method].apply(this, arguments);
            if (callback) {
              var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
              
              var to_print = {
                category: category,
                class: clazz,
                method: method,
                args: args_string_value,
                calledFrom: calledFrom,
                result: retval ? retval.toString() : null,
              };
              retval = callback(retval, to_print);

            }
            return retval;
        }
      } else {
      
        for (var i = 0; i < toHook.overloads.length; i++) {
          var args_string_value = []
          toHook.overloads[i].implementation = function () {
            
            if (arguments !== undefined) {
              var args = [].slice.call(arguments);
              // send('API Monitor - '+ typeof args)
              
              if (args !== undefined){
                for (var k = 0, l = args.length; k < l; k++) {
                  args_string_value.push(args[k] + "");
                }
              }
            }
            
            // Call original method
            var retval = this[method].apply(this, arguments);

            if (callback) {
              var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
              var to_print = {
                category: category,
                class: clazz,
                method: method,
                args: args_string_value,
                calledFrom: calledFrom,
                result: retval ? retval.toString() : null,
              };
              retval = callback(retval, to_print);
            }
            return retval;
          }
        }
      }
    } catch (err) {
      send('API Monitor - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
    }
  }