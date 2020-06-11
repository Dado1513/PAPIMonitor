// use onLoad function to run 'callback' just after 'libname' lib is loaded (and before anything else is processed)
// e.g. libname is 'c' for library 'libc.so' (see https://developer.android.com/reference/java/lang/System#loadLibrary(java.lang.String))

function onLoad(libname, callback) {
    Java.perform(function() {
        var Runtime = Java.use('java.lang.Runtime');
        var System = Java.use('java.lang.System');
        var VMStack = Java.use('dalvik.system.VMStack');
        var VERSION = Java.use('android.os.Build$VERSION');
        System.loadLibrary.overload('java.lang.String').implementation = function(currentLibname) {
            if (VERSION.SDK_INT.value >= 29) {
                Runtime.getRuntime().loadLibrary0(Java.use('sun.reflect.Reflection').getCallerClass(), currentLibname);
            } else if (VERSION.SDK_INT.value >= 24) {
                Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), currentLibname);
            } else {
                Runtime.getRuntime().loadLibrary(currentLibname, VMStack.getCallingClassLoader());
            }
            if(currentLibname === libname) {
                callback();
            }
        };
    });
}
