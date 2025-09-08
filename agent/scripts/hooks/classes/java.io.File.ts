import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.io.File class to bypass file system root detection.
 */
export namespace JavaIoFile {
    const NAME = "[File]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    const ROOT_BINARIES = [
        "su",
        "busybox",
        "supersu",
        "Superuser.apk",
        "KingoUser.apk",
        "SuperSu.apk"
    ];
    
    const FILE_SYSTEM: Record<string, { exists?: boolean, read?: boolean, write?: boolean }> = {
        "/": {
            write: false
        },
        "/data": {
            write: false,
            read: false
        },
        "/data/local/bin/su": {
            exists: false
        },
        "/data/local/su": {
            exists: false
        },
        "/data/local/xbin/su": {
            exists: false
        },
        "/dev": {
            write: false
        },
        "/etc": {
            write: false
        },
        "/proc": {
            write: false
        },
        "/sbin": {
            write: false
        },
        "/sbin/su": {
            exists: false
        },
        "/sys": {
            write: false
        },
        "/system/bin/failsafe/su": {
            exists: false
        },
        "/system/bin/su": {
            exists: false
        },
        "/system/sd/xbin/su": {
            exists: false
        },
        "/system/xbin/su": {
            exists: false
        },
        "/etc/security/otacerts.zip": {
            exists: true
        }
    };

    export function performNow(): void {
        try {
            antiRoot();
            monitorFiles();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Preventing application from using File System to validate rooting access permissions.
     */
    function antiRoot(): void {
        try {
            const File = Java.use("java.io.File");
            
            File.exists.implementation = function() {
                const name = this.getName();
                const override = FILE_SYSTEM[name];

                if (ROOT_BINARIES.includes(name)){
                    log(`File.exists: ${name} -> false`);
                    return false;
                } else if (override && override.exists !== undefined) {
                    log(`File.exists: ${name} -> ${override.exists}`);
                    return override.exists;
                } else {
                    return this.exists.call(this);
                }
            };
        
            File.canWrite.implementation = function() {
                const name = this.getName();
                const override = FILE_SYSTEM[name];

                if (override && override.write !== undefined) {
                    log(`File.canWrite: ${name} -> ${override.write}`);
                    return override.write;
                } else {
                    return this.canWrite.call(this);
                }
            };
        
            File.canRead.implementation = function() {
                const name = this.getName();
                const override = FILE_SYSTEM[name];

                if (override && override.read !== undefined) {
                    log(`File.canRead: ${name} -> ${override.read}`);
                    return override.read;
                } else {
                    return this.canRead.call(this);
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `antiRoot failed: ${error}`);
        }
    }

    /**
     * Monitor file operations for debugging and analysis purposes.
     */
    function monitorFiles(): void {
        try {
            const File = Java.use("java.io.File");
            const FileInputStream = Java.use("java.io.FileInputStream");

            try {
                const fileConstr1 = File.$init.overload("java.lang.String");
                fileConstr1.implementation = function (a0: any) {
                    log(`New file (1): ${a0}`);
                    return fileConstr1.call(this, a0);
                };
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `New file (1) failed: ${error}`);
            }

            try {
                const fileConstr2 = File.$init.overload("java.lang.String", "java.lang.String");
                fileConstr2.implementation = function (a0: any, a1: any) {
                    log(`New file (2): ${a0}/${a1}`);
                    return fileConstr2.call(this, a0, a1);
                };
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `New file (2) failed: ${error}`);
            }

            try {
                const fileInputStreamConstr = FileInputStream.$init.overload("java.io.File");
                fileInputStreamConstr.implementation = function (a0: any) {
                    try {
                        const file = Java.cast(a0, File);
                        const path = file.getAbsolutePath();
                        log(`New FileInputStream: ${path}`);
                    } catch (error) {
                        log(`New FileInputStream (couldn't read filepath)`);
                    }
                    return fileInputStreamConstr.call(this, a0);
                };
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `New FileInputStream failed: ${error}`);
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `monitorFiles failed: ${error}`);
        }
    }
}