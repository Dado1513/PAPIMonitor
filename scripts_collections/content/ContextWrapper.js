/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.content.ContextWrapper";
    var target = Java.use(cn);
    if (target) {
        target.createPackageContext.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "createPackageContext";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.createPackageContext.apply(this, arguments);
        };

        target.removeStickyBroadcast.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "removeStickyBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.removeStickyBroadcast.apply(this, arguments);
        };

        target.console.logBroadcast.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logBroadcast.overloads[0].apply(this, arguments);
        };
        target.console.logBroadcast.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logBroadcast.overloads[1].apply(this, arguments);
        };

        target.console.logBroadcastAsUser.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logBroadcastAsUser";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logBroadcastAsUser.overloads[0].apply(this, arguments);
        };
        target.console.logBroadcastAsUser.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logBroadcastAsUser";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logBroadcastAsUser.overloads[1].apply(this, arguments);
        };

        target.console.logOrderedBroadcast.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logOrderedBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logOrderedBroadcast.overloads[0].apply(this, arguments);
        };
        target.console.logOrderedBroadcast.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logOrderedBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logOrderedBroadcast.overloads[1].apply(this, arguments);
        };
        target.console.logOrderedBroadcast.overloads[2].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logOrderedBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logOrderedBroadcast.overloads[2].apply(this, arguments);
        };
        target.console.logOrderedBroadcast.overloads[3].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logOrderedBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logOrderedBroadcast.overloads[3].apply(this, arguments);
        };

        target.console.logOrderedBroadcastAsUser.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logOrderedBroadcastAsUser";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logOrderedBroadcastAsUser.overloads[0].apply(this, arguments);
        };
        target.console.logOrderedBroadcastAsUser.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logOrderedBroadcastAsUser";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logOrderedBroadcastAsUser.overloads[1].apply(this, arguments);
        };
        target.console.logOrderedBroadcastAsUser.overloads[2].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logOrderedBroadcastAsUser";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logOrderedBroadcastAsUser.overloads[2].apply(this, arguments);
        };

        target.console.logStickyBroadcast.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logStickyBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logStickyBroadcast.apply(this, arguments);
        };

        target.console.logStickyBroadcastAsUser.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logStickyBroadcastAsUser";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logStickyBroadcastAsUser.apply(this, arguments);
        };

        target.console.logStickyOrderedBroadcast.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logStickyOrderedBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logStickyOrderedBroadcast.apply(this, arguments);
        };

        target.console.logStickyOrderedBroadcastAsUser.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "console.logStickyOrderedBroadcastAsUser";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            console.log(myArray);
            return this.console.logStickyOrderedBroadcastAsUser.apply(this, arguments);
        };
    }
});