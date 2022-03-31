

Java.perform(function(){    
  console.log("log widget");
  var clazz = Java.use("android.widget.Toast");
  console.log("clazz");
  var toHook = clazz.makeText;
  console.log(toHook.toString());
  console.log(toHook.overloads.length);
  for (var i = 0; i < toHook.overloads.length; i++) {
    var ctor = toHook.overloads[i];
    console.log(ctor);
    ctor.implementation = function (arguments) {
      console.log("imp")
    }
    //  var args = [].slice.call(arguments);
    //  Call original method
    //  var retval = ctor.call(this, arguments);
    //}
    // 
  }
});


/*console.log("Hooked: "+toHook.overloads[i])
toHook.overloads[i].implementation = function () {
    console.log()
    var args = [].slice.call(arguments);
    console.log(arguments);
    // Call original method
    var retval = this[method].call(this, arguments);
    return retval;
}*/