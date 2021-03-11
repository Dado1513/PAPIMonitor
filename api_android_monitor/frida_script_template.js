Java.perform(function () {
    var cn = class_name;
    var clazz = Java.use(cn);
    var func = method_name;
    var overloads = clazz[func].overloads;
    for (var i in overloads) {
        if (overloads[i].hasOwnProperty('argumentTypes')) {
            var parameters = [];
            var curArgumentTypes = overloads[i].argumentTypes;
            var args = [];
            var argLog = '[';
            var value_parameters = "[";
            for (var j in curArgumentTypes) {
                var cName = curArgumentTypes[j].className;
                parameters.push(cName);
                argLog += "'(" + cName + ") ' + v" + j + ",";
                value_parameters += "v" + j + " ,";
                args.push('v' + j);
            }

            argLog += ']';
            value_parameters += "]";


            var script = "var ret = this." + func + '(' + args.join(',') + ") || '';\n"
                + "send({className:'" + cn + "', method:'" + func + "', parameters: " + value_parameters + ", return: ret});\n"
                + "return ret;";
            args.push(script);
            clazz[func].overload.apply(this, parameters).implementation = Function.apply(null, args);
        }
    }

});