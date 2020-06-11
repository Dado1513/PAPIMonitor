/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "android.telephony.SmsManager";
    var smsManager = Java.use(cn);
    if (smsManager) {
        //hook console.logTextMessage
        smsManager.console.logTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logTextMessage.overloads[0].apply(this, arguments);
        };
        //hook console.logDataMessage
        smsManager.console.logDataMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logDataMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logDataMessage.overloads[0].apply(this, arguments);
        };
        //hook console.logMultipartTextMessage
        smsManager.console.logMultipartTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logMultipartTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logMultipartTextMessage.overloads[0].apply(this, arguments);
        };

        smsManager.console.logTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logTextMessage.overloads[0].apply(this, arguments);
        };

        smsManager.console.logTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logTextMessage.overloads[0].apply(this, arguments);
        };

        smsManager.divideMessage.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "divideMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.divideMessage.apply(this, arguments);
        };

        smsManager.downloadMultimediaMessage.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "downloadMultimediaMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.downloadMultimediaMessage.apply(this, arguments);
        };

        smsManager.console.logMultimediaMessage.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logMultimediaMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logMultimediaMessage.apply(this, arguments);
        };
    }
});
