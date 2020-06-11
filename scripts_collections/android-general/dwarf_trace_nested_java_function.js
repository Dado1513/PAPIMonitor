/* startJavaTracer is a Dwarf api. The implemented callbacks will give a similar output
|--------> org.json.JSONObject.toString   ( )
|
|------------> org.json.JSONObject.writeTo   ( null (org.json.JSONStringer) )
|
|----------------> org.json.JSONObject.writeTo   ( {"rs":[ (org.json.JSONStringer) )
|
|--------------------> org.json.JSONObject.writeTo   ( {"rs":[{"sers" (org.json.JSONStringer) )
|
|------------------------> org.json.JSONObject.numberToString   ( 1590597498541 (java.lang.Long) )
|
|------------------------> org.json.JSONObject.writeTo   ( {"rs":[{"sers":{"ts":null,"ls":[ (org.json.JSONStringer) )
|<------------------------ org.json.JSONObject writeTo void
|
|------------------------> org.json.JSONObject.writeTo   ( {"rs":[{"sers":{"ts":null,"ls":[{"sn":"com.mufc.fireuvw.MainService","pn":"com.mufc.fireuvw"} (org.json.JSONStringer) )
|<------------------------ org.json.JSONObject writeTo void
|<-------------------- org.json.JSONObject writeTo void
|<---------------- org.json.JSONObject writeTo void
 */
startJavaTracer(['list', 'of', 'target', 'classes'], {
    onEnter: function () {
        console.log('|');
        this.nullDepthLine = ('\t'.repeat(this.depth));
        this.depthLine = ('----'.repeat(this.nullDepthLine.length));
        var r = ['|' + this.depthLine + '>', this.$className + '.' + this.method];
        r.push('  (')
        for (var i=0;i<arguments.length;i++) {
            var clazzName = '';
            if (typeof arguments[i].$className !== 'undefined') {
                clazzName = arguments[i].$className;
                clazzName = ' (' + clazzName + ')'
            }
            r.push(arguments[i].toString() + clazzName + (i < arguments.length - 1 ? ',' : ''));
        }
        r.push(')')
        console.log(r.join(' '));
    },
    onLeave: function (ret) {
        if (typeof ret === 'undefined') {
            ret = 'void';
        } else if (ret === null) {
            ret = 'null';
        }
        console.log('|<' + this.depthLine, this.$className, this.method, ret.toString());
    }
})