import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

enum Action {
    contains,
    get,
    put,
    remove
}

enum Type {
    int,
    float,
    long,
    boolean,
    string,
    stringSet,
    none
}

/**
 * Hook for android.app.SharedPreferencesImpl class to monitor SharedPreferences access.
 */
export namespace SharedPreferencesImpl {
    const NAME = "[SharedPreferencesImpl]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    let targets: [string];

    export function initialize(targetList: [string]) {
        targets = targetList;
    }

    export function performNow(): void {
        try {
            const SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
            const File = Java.use("java.io.File");

            SharedPreferencesImpl.contains.implementation = function (key: any) {
                var value = this.contains(key);
                var sharedPreferencesFile = Java.cast(this.mFile.value, Java.use("java.io.File"));

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.contains, Type.none, key, null, value);
                        }
                    });
                }
                return value;
            };

            //getInt
            SharedPreferencesImpl.getInt.implementation = function (key: any, defValue: any) {
                var value = this.getInt(key, defValue);
                var sharedPreferencesFile = Java.cast(this.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.get, Type.int, key, defValue, value);
                        }
                    });
                }
                return value;
            };

            //getFloat
            SharedPreferencesImpl.getFloat.implementation = function (key: any, defValue: any) {
                var value = this.getFloat(key, defValue);
                var sharedPreferencesFile = Java.cast(this.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.get, Type.float, key, defValue, value);
                        }
                    });
                }
                return value;
            };

            //getLong
            SharedPreferencesImpl.getLong.implementation = function (key: any, defValue: any) {
                var value = this.getLong(key, defValue);
                var sharedPreferencesFile = Java.cast(this.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.get, Type.long, key, defValue, value);
                        }
                    });
                }
                return value;
            };

            //getBoolean
            SharedPreferencesImpl.getBoolean.implementation = function (key: any, defValue: any) {
                var value = this.getBoolean(key, defValue);
                var sharedPreferencesFile = Java.cast(this.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.get, Type.boolean, key, defValue, value);
                        }
                    });
                }
                return value;
            };

            //getString
            SharedPreferencesImpl.getString.implementation = function (key: any, defValue: any) {
                var value = this.getString(key, defValue);
                var sharedPreferencesFile = Java.cast(this.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.get, Type.string, key, defValue, value);
                        }
                    });
                }
                return value;
            };

            //getStringSet
            SharedPreferencesImpl.getStringSet.implementation = function (key: any, defValue: any) {
                var value = this.getStringSet(key, defValue);
                var sharedPreferencesFile = Java.cast(this.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.get, Type.stringSet, key, defValue, value);
                        }
                    });
                }
                return value;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    function printData(target: string, action: Action, type: Type, key: any, defValue: any, value: any) {
        var message = "Event at: " + target;

        switch (action) {
            case Action.contains:
                message = message.concat("\n ⋂ CONTAINS");
                break;
            case Action.get:
                message = message.concat("\n ← GET: " + Type[type]);
                break;
            case Action.put:
                message = message.concat("\n → PUT: " + Type[type]);
                break;
            case Action.remove:
                message = message.concat("\n x REMOVE");
                break;
        }
        message = message.concat("\n  \- Key: " + key);
        message = message.concat("\n  \- Default: " + defValue);
        message = message.concat("\n  \- Value: " + value);

        log(message);
    }
}