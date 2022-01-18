import { Logger } from "../../utils/logger";

export namespace Rooting {
    const NAME = "[Anti-Rooting]";
    const LOG_TYPE = Logger.Type.Debug

    /**
    * Hooked classes
    */
    const _PackageManager = Java.use("android.app.ApplicationPackageManager");
    const _NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
    const _File = Java.use("java.io.File");
    const _Runtime = Java.use('java.lang.Runtime');
    const _ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    const _SystemProperties = Java.use('android.os.SystemProperties');
    const _String = Java.use('java.lang.String');
    const _BufferedReader = Java.use('java.io.BufferedReader');

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
    
    const FILE_SYSTEM: Record < string, { exists ? : boolean, read ? : boolean, write ? : boolean } > = {
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
     * Perform hooks on the system to bypass anti-rooting validations.
     * 
     */
     export function hook() {
        Logger.log(Logger.Type.Config, NAME, "Hooks loaded.");
        try {
            packageManager()
            fileSystem()
            runtimeExecutions()
            systemProperties()
            testKeysValidations()
            nativeValidations() 
        } catch(error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed.\n${error}`);
        }
    }

    /**
    * Preventing application from access and retrieve information about rooting packages.
    */
    function packageManager() {
        _PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName: string, flags: number) {
            if (ROOTING_PACKAGES.includes(packageName)) {
                Logger.log(LOG_TYPE, NAME, `PM.getPackageInfo: ${packageName}`);
                throw _NameNotFoundException.$new(packageName);
            }

            return this.getPackageInfo.call(this, packageName, flags);
        };
    }

    /**
    * Preventing application from using File System to validate access permissions.
    */
    function fileSystem() {
        _File.exists.implementation = function() {
            const name = this.getName();
            const override = FILE_SYSTEM[name];

            if (ROOT_BINARIES.includes(name)){
                Logger.log(LOG_TYPE, NAME, `File.exists: ${name} -> false`);
                return false;
            } else if (override && override.exists !== undefined) {
                Logger.log(LOG_TYPE, NAME, `File.exists: ${name} -> ${override.exists}`);
                return override.exists;
            } else {
                return this.exists.call(this);
            }
        };
    
        _File.canWrite.implementation = function() {
            const name = this.getName();
            const override = FILE_SYSTEM[name];

            if (override && override.write !== undefined) {
                Logger.log(LOG_TYPE, NAME, `File.exists: ${name} -> ${override.write}`);
                return override.write;
            } else {
                return this.canWrite.call(this);
            }
        };
    
        _File.canRead.implementation = function() {
            const name = this.getName();
            const override = FILE_SYSTEM[name];

            if (override && override.read !== undefined) {
                Logger.log(LOG_TYPE, NAME, `File.exists: ${name} -> ${override.read}`);
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
        _Runtime.exec.overloads.forEach((overload:any) => {
            overload.implementation = function (...args: any) {
                if (typeof args[0] === 'string' || args[0] instanceof String) {
                    var cmd = args[0].toString()

                    if ((cmd.indexOf("getprop") != -1)
                    || (cmd == "mount")
                    || (cmd.indexOf("build.prop") != -1)
                    || (cmd == "id")
                    || (cmd == "sh")) {
                        Logger.log(LOG_TYPE, NAME, `Runtime.exec: ${cmd}`);
                        return this.exec.call(this, "grep");
                    }
                    if (cmd == "su") {
                        Logger.log(LOG_TYPE, NAME, `Runtime.exec: ${cmd}`);
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
                            Logger.log(LOG_TYPE, NAME, `Runtime.exec: ${array}`);
                            return this.exec.call(this, "grep");
                        }
                        if (tmp_cmd == "su") {
                            Logger.log(LOG_TYPE, NAME, `Runtime.exec: ${array}`);
                            return this.exec.call(this, "loremipsum");
                        }
                    }

                    return this.exec.call(this, ...args);
                }
            }
        });

        _ProcessBuilder.start.implementation = function () {
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
                Logger.log(LOG_TYPE, NAME, `ProcessBuilder.start: ${cmd}`);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                Logger.log(LOG_TYPE, NAME, `ProcessBuilder.start: ${cmd}`);
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
        _SystemProperties.get.overload('java.lang.String').implementation = function(name:string) {
            switch(name) {
                case "ro.build.selinux":
                    Logger.log(LOG_TYPE, NAME, `SystemProperties.get: ${name} -> 1`);
                    return "1";
                case "ro.debuggable":
                    Logger.log(LOG_TYPE, NAME, `SystemProperties.get: ${name} -> 0`);
                    return "0";
                case "service.adb.root":
                    Logger.log(LOG_TYPE, NAME, `SystemProperties.get: ${name} -> 0`);
                    return "0";
                case "ro.secure":
                    Logger.log(LOG_TYPE, NAME, `SystemProperties.get: ${name} -> 1`);
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
        _String.contains.implementation = function(name:string) {
            switch(name) {
                case "test-keys":
                    Logger.log(LOG_TYPE, NAME, `String.contains: ${name} -> false`);
                    return false;
                default:
                    return this.contains.call(this, name);
                    
            }
        };

        _BufferedReader.readLine.overloads.forEach((overload:any) => {
            overload.implementation = function (...args: any) {
                var text = this.readLine.call(this, ...args);

                if (text !== null && text.indexOf("ro.build.tags=test-keys") > -1) {
                    Logger.log(LOG_TYPE, NAME, `BufferedReader.readLine: ${text} -> ro.build.tags=release-keys`);
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
        Interceptor.attach(Module.findExportByName("libc.so", "system")!, {
            onEnter: function(args) {
                var cmd = this.readCString(args[0]);

                if (cmd.indexOf("getprop") != -1 
                || cmd == "mount" 
                || cmd.indexOf("build.prop") != -1 
                || cmd == "id") {
                    Logger.log(LOG_TYPE, NAME, `Native libc.so: ${cmd}`);
                    this.writeUtf8String(args[0], "grep");
                }

                if (cmd == "su") {
                    Logger.log(LOG_TYPE, NAME, `Native libc.so: ${cmd}`);
                    this.writeUtf8String(args[0], "loremipsum");
                }
            },
            onLeave: function(retval) {}
        });
    }
}

