/**
 * common calls for su and various detections
 */

Interceptor.attach(Module.findExportByName(null, 'faccessat'), function (args) {
    console.log('faccessat', args[1].readUtf8String());
});

Interceptor.attach(Module.findExportByName(null, 'open'), function (args) {
    console.log('open', args[0].readUtf8String());
});

Interceptor.attach(Module.findExportByName(null, 'stat'), function (args) {
    console.log('stat', args[0].readUtf8String());
});

Interceptor.attach(Module.findExportByName(null, 'access'), function (args) {
    console.log('access', args[0].readUtf8String());
});

Interceptor.attach(Module.findExportByName(null, 'system'), function (args) {
    console.log('system', args[0].readUtf8String());
});