// intercept libc open
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function (args) {
        let file_path = Memory.readUtf8String(args[0]);
        this.file_path = file_path;

        let file_name = file_path.split("/").pop();
        this.file_name = file_name;
    },
    onLeave: function (retval) {
        if (this.file_name == "BACKUP_META_DATA") {
            retval.replace(-1);
            /* -1 means failure to open file, game thinks it's not there and
            so doesn't upload tracked items to the game server
            */
            log("Intercepted open() for BACKUP_META_DATA file");
        }
    }
});
