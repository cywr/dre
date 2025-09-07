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
    };

    export function performNow(): void {
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
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}