import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";

/**
 * Perform hooks on the system to bypass anti-rooting validations.
*/

export class Rooting implements Hook {
    NAME = "[Anti-Rooting]";
    LOG_TYPE = Logger.Type.Debug

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Debug`
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

    execute(): void {
        this.info()
        try {
            this.packageManager(this)
            this.fileSystem(this)
            this.runtimeExecutions(this)
            this.systemProperties(this)
            this.testKeysValidations(this)
            this.nativeValidations(this) 
        } catch(error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`)
        }
    }

    /** Hooked classes */
    _PackageManager = Java.use("android.app.ApplicationPackageManager");
    _File = Java.use("java.io.File");
    _Runtime = Java.use('java.lang.Runtime');
    _ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    _SystemProperties = Java.use('android.os.SystemProperties');
    _String = Java.use('java.lang.String');
    _BufferedReader = Java.use('java.io.BufferedReader');

    _NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");

    /** Lists */
    ROOTING_PACKAGES = [
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
    
    ROOT_BINARIES = [
        "su",
        "busybox",
        "supersu",
        "Superuser.apk",
        "KingoUser.apk",
        "SuperSu.apk"
    ];
    
    FILE_SYSTEM: Record < string, { exists ? : boolean, read ? : boolean, write ? : boolean } > = {
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
    packageManager(_this: Rooting) { 
        _this._PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName: string, flags: number) {
            if (_this.ROOTING_PACKAGES.includes(packageName)) {
                Logger.log(_this.LOG_TYPE, _this.NAME, `PM.getPackageInfo: ${packageName}`);
                throw this._NameNotFoundException.$new(packageName);
            }

            return this.getPackageInfo.call(this, packageName, flags);
        };
    }

    /**
    * Preventing application from using File System to validate access permissions.
    */
    fileSystem(_this: Rooting) {
        _this._File.exists.implementation = function() {
            const name = this.getName();
            const override = _this.FILE_SYSTEM[name];

            if (_this.ROOT_BINARIES.includes(name)){
                Logger.log(_this.LOG_TYPE, _this.NAME, `File.exists: ${name} -> false`);
                return false;
            } else if (override && override.exists !== undefined) {
                Logger.log(_this.LOG_TYPE, _this.NAME, `File.exists: ${name} -> ${override.exists}`);
                return override.exists;
            } else {
                return this.exists.call(this);
            }
        };
    
        _this._File.canWrite.implementation = function() {
            const name = this.getName();
            const override = _this.FILE_SYSTEM[name];

            if (override && override.write !== undefined) {
                Logger.log(_this.LOG_TYPE, _this.NAME, `File.exists: ${name} -> ${override.write}`);
                return override.write;
            } else {
                return this.canWrite.call(this);
            }
        };
    
        _this._File.canRead.implementation = function() {
            const name = this.getName();
            const override = _this.FILE_SYSTEM[name];

            if (override && override.read !== undefined) {
                Logger.log(_this.LOG_TYPE, _this.NAME, `File.exists: ${name} -> ${override.read}`);
                return override.read;
            } else {
                return this.canRead.call(this);
            }
        };
    }

    /**
    * Preventing application from executing commands to evaluate system permissions.
    */
    runtimeExecutions(_this: Rooting) {
        _this._Runtime.exec.overloads.forEach((overload:any) => {
            overload.implementation = function (...args: any) {
                if (typeof args[0] === 'string' || args[0] instanceof String) {
                    var cmd = args[0].toString()

                    if ((cmd.indexOf("getprop") != -1)
                    || (cmd == "mount")
                    || (cmd.indexOf("build.prop") != -1)
                    || (cmd == "id")
                    || (cmd == "sh")) {
                        Logger.log(_this.LOG_TYPE, _this.NAME, `Runtime.exec: ${cmd}`);
                        return this.exec.call(this, "grep");
                    }
                    if (cmd == "su") {
                        Logger.log(_this.LOG_TYPE, _this.NAME, `Runtime.exec: ${cmd}`);
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
                            Logger.log(_this.LOG_TYPE, _this.NAME, `Runtime.exec: ${array}`);
                            return this.exec.call(this, "grep");
                        }
                        if (tmp_cmd == "su") {
                            Logger.log(_this.LOG_TYPE, _this.NAME, `Runtime.exec: ${array}`);
                            return this.exec.call(this, "loremipsum");
                        }
                    }

                    return this.exec.call(this, ...args);
                }
            }
        });

        _this._ProcessBuilder.start.implementation = function () {
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
                Logger.log(_this.LOG_TYPE, _this.NAME, `ProcessBuilder.start: ${cmd}`);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                Logger.log(_this.LOG_TYPE, _this.NAME, `ProcessBuilder.start: ${cmd}`);
                this.command.call(this, ["loremipsum"]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };
    }

    /**
    * Preventing application from retrieving system properties related to rooting.
    */
    systemProperties(_this: Rooting){
        _this._SystemProperties.get.overload('java.lang.String').implementation = function(name:string) {
            switch(name) {
                case "ro.build.selinux":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SystemProperties.get: ${name} -> 1`);
                    return "1";
                case "ro.debuggable":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SystemProperties.get: ${name} -> 0`);
                    return "0";
                case "service.adb.root":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SystemProperties.get: ${name} -> 0`);
                    return "0";
                case "ro.secure":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SystemProperties.get: ${name} -> 1`);
                    return "1";
                default:
                    return this.get.call(this, name);
                    
            }
        };
    }

    /**
    * Preventing application from validating test-keys;
    */
    testKeysValidations(_this: Rooting){
        _this._String.contains.implementation = function(name:string) {
            switch(name) {
                case "test-keys":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `String.contains: ${name} -> false`);
                    return false;
                default:
                    return this.contains.call(this, name);
                    
            }
        };

        _this._BufferedReader.readLine.overloads.forEach((overload:any) => {
            overload.implementation = function (...args: any) {
                var text = this.readLine.call(this, ...args);

                if (text !== null && text.indexOf("ro.build.tags=test-keys") > -1) {
                    Logger.log(_this.LOG_TYPE, _this.NAME, `BufferedReader.readLine: ${text} -> ro.build.tags=release-keys`);
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }

                return text;
            }
        });
    }

    /**
    * Preventing application from validating rooting through native;
    */
    nativeValidations(_this: Rooting){
        Interceptor.attach(Module.findExportByName("libc.so", "system")!, {
            onEnter: function(args) {
                var cmd = this.readCString(args[0]);

                if (cmd.indexOf("getprop") != -1 
                || cmd == "mount" 
                || cmd.indexOf("build.prop") != -1 
                || cmd == "id") {
                    Logger.log(_this.LOG_TYPE, _this.NAME, `Native libc.so: ${cmd}`);
                    this.writeUtf8String(args[0], "grep");
                }

                if (cmd == "su") {
                    Logger.log(_this.LOG_TYPE, _this.NAME, `Native libc.so: ${cmd}`);
                    this.writeUtf8String(args[0], "loremipsum");
                }
            },
            onLeave: function(retval) {}
        });
    }
}

