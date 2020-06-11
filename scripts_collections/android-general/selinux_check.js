var selinuxFd = -1;

Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(ret) {
        if (this.path === '/sys/fs/selinux/enforce') {
            selinuxFd = parseInt(ret);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, 'read'), {
    onEnter: function(args) {
        this.fd = args[0];
        this.buf = args[1];
    },
    onLeave: function(ret) {
        if (parseInt(this.fd) === selinuxFd) {
            selinuxFd = -1;
            this.buf.writeU8(1);
        }
    }
});
