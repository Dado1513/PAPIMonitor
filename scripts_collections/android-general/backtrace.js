function backtrace() {
    Java.perform(function () {
        console.log(Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
    })
}