import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Perform hooks on the system to bypass anti-rooting validations.
 */
export namespace Rooting {
    const NAME = "[Anti-Rooting]"
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message)

    export function performNow(): void {
        info()
        try {
            packageManager()
            fileSystem()
            runtimeExecutions()
            systemProperties()
            testKeysValidations()
            nativeValidations() 
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`)
        }
    }

    function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Debug`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.app.ApplicationPackageManager \x1b[0m`
            + `\n║ │ └── getPackageInfo`
            + `\n║ ├─┬\x1b[35m java.io.File \x1b[0m`
            + `\n║ │ ├── exists`
            + `\n║ │ ├── canWrite`
            + `\n║ │ └── canRead`
            + `\n║ ├─┬\x1b[35m java.lang.Runtime \x1b[0m`
            + `\n║ │ └── exec`
            + `\n║ ├─┬\x1b[35m java.lang.ProcessBuilder \x1b[0m`
            + `\n║ │ └── start`
            + `\n║ ├─┬\x1b[35m android.os.SystemProperties \x1b[0m`
            + `\n║ │ └── get`
            + `\n║ ├─┬\x1b[35m java.lang.String \x1b[0m`
            + `\n║ │ └── contains`
            + `\n║ └─┬\x1b[35m java.io.BufferedReader \x1b[0m`
            + `\n║   └── readLine`
            + `\n╟─┬\x1b[31m Native Files \x1b[0m`
            + `\n║ └─┬\x1b[35m libc.so \x1b[0m`
            + `\n║   └── system`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    const ROOTING_PACKAGES = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer",
        "com.saurik.substrate",
        "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree",
        "com.formyhm.hiderootPremium",
        "com.formyhm.hideroot",
        "me.phh.superuser",
        "eu.chainfire.supersu.pro",
        "com.kingouser.com"
    ];
    
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

    /**
     * Preventing application from access and retrieve information about rooting packages.
     */
    function packageManager() {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        const NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
        
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName: string, flags: number) {
            if (ROOTING_PACKAGES.includes(packageName)) {
                log(`PM.getPackageInfo: hiding ${packageName}`);
                throw NameNotFoundException.$new(packageName);
            }

            return this.getPackageInfo.call(this, packageName, flags);
        };
    }

    /**
     * Preventing application from using File System to validate access permissions.
     */
    function fileSystem() {
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
    }

    /**
     * Preventing application from executing commands to evaluate system permissions.
     */
    function runtimeExecutions() {
        const Runtime = Java.use('java.lang.Runtime');
        const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        
        Runtime.exec.overloads.forEach((overload:any) => {
            overload.implementation = function (...args: any) {
                if (typeof args[0] === 'string' || args[0] instanceof String) {
                    var cmd = args[0].toString()

                    if ((cmd.indexOf("getprop") != -1)
                    || (cmd == "mount")
                    || (cmd.indexOf("build.prop") != -1)
                    || (cmd == "id")
                    || (cmd == "sh")) {
                        log( `Runtime.exec: ${cmd}`);
                        return this.exec.call(this, "grep");
                    }
                    if (cmd == "su") {
                        log( `Runtime.exec: ${cmd}`);
                        return this.exec.call(this, "loremipsum");
                    }

                    return this.exec.call(this, ...args);
                } else {
                    var array = args[0]
                    
                    for (var i = 0; i < array.length; i = i + 1) {
                        var tmp_cmd = array[i];
        
                        if ((tmp_cmd.indexOf("getprop") != -1)
                        || (tmp_cmd == "mount")
                        || (tmp_cmd.indexOf("build.prop") != -1) 
                        || (tmp_cmd == "id") 
                        || (tmp_cmd == "sh")) {
                            log( `Runtime.exec: ${array}`);
                            return this.exec.call(this, "grep");
                        }
                        if (tmp_cmd == "su") {
                            log( `Runtime.exec: ${array}`);
                            return this.exec.call(this, "loremipsum");
                        }
                    }

                    return this.exec.call(this, ...args);
                }
            }
        });

        ProcessBuilder.start.implementation = function () {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();

                if (tmp_cmd.indexOf("getprop") != -1 
                || tmp_cmd.indexOf("mount") != -1 
                || tmp_cmd.indexOf("build.prop") != -1 
                || tmp_cmd.indexOf("id") != -1) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                log( `ProcessBuilder.start: ${cmd}`);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                log( `ProcessBuilder.start: ${cmd}`);
                this.command.call(this, ["loremipsum"]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };
    }

    /**
     * Preventing application from retrieving system properties related to rooting.
     */
    function systemProperties(){
        const SystemProperties = Java.use('android.os.SystemProperties');
        
        SystemProperties.get.overload('java.lang.String').implementation = function(name:string) {
            switch(name) {
                case "ro.build.selinux":
                    log( `SystemProperties.get: ${name} -> 1`);
                    return "1";
                case "ro.debuggable":
                    log( `SystemProperties.get: ${name} -> 0`);
                    return "0";
                case "service.adb.root":
                    log( `SystemProperties.get: ${name} -> 0`);
                    return "0";
                case "ro.secure":
                    log( `SystemProperties.get: ${name} -> 1`);
                    return "1";
                default:
                    return this.get.call(this, name);
                    
            }
        };
    }

    /**
     * Preventing application from validating test-keys;
     */
    function testKeysValidations(){
        const String = Java.use('java.lang.String');
        const BufferedReader = Java.use('java.io.BufferedReader');
        
        String.contains.implementation = function(name:string) {
            switch(name) {
                case "test-keys":
                    log( `String.contains: ${name} -> false`);
                    return false;
                default:
                    return this.contains.call(this, name);
                    
            }
        };

        BufferedReader.readLine.overloads.forEach((overload:any) => {
            overload.implementation = function (...args: any) {
                var text = this.readLine.call(this, ...args);

                if (text !== null && text.indexOf("ro.build.tags=test-keys") > -1) {
                    log( `BufferedReader.readLine: ${text} -> ro.build.tags=release-keys`);
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }

                return text;
            }
        });
    }

    /**
     * Preventing application from validating rooting through native;
     */
    function nativeValidations(){
        Interceptor.attach((Module as any).findExportByName("libc.so", "system")!, {
            onEnter: function(args) {
                var cmd = this.readCString(args[0]);

                if (cmd.indexOf("getprop") != -1 
                || cmd == "mount" 
                || cmd.indexOf("build.prop") != -1 
                || cmd == "id") {
                    log( `Native libc.so: ${cmd}`);
                    this.writeUtf8String(args[0], "grep");
                }

                if (cmd == "su") {
                    log( `Native libc.so: ${cmd}`);
                    this.writeUtf8String(args[0], "loremipsum");
                }
            },
            onLeave: function(retval) {}
        });
    }
}

