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
 * Hook for android.app.SharedPreferencesImpl$EditorImpl class to monitor SharedPreferences editing.
 */
export namespace AndroidAppSharedPreferencesImplEditorImpl {
    const NAME = "[SharedPreferencesImpl.EditorImpl]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    let targets: [string];

    export function initialize(targetList: [string]) {
        targets = targetList;
    }

    export function performNow(): void {
        try {
            const SharedPreferencesImpl_EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
            const File = Java.use("java.io.File");

            //putString
            SharedPreferencesImpl_EditorImpl.putString.implementation = function (key: any, value: any) {
                var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.put, Type.string, key, null, value);
                        }
                    });
                }
                return this.putString(key, value);
            };

            //putStringSet
            SharedPreferencesImpl_EditorImpl.putStringSet.implementation = function (key: any, values: any) {
                var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.put, Type.stringSet, key, null, values);
                        }
                    });
                }
                return this.putStringSet(key, values);
            };

            //putInt
            SharedPreferencesImpl_EditorImpl.putInt.implementation = function (key: any, value: any) {
                var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.put, Type.int, key, null, value);
                        }
                    });
                }
                return this.putInt(key, value);
            };

            //putFloat
            SharedPreferencesImpl_EditorImpl.putFloat.implementation = function (key: any, value: any) {
                var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.put, Type.float, key, null, value);
                        }
                    });
                }
                return this.putFloat(key, value);
            };

            //putLong
            SharedPreferencesImpl_EditorImpl.putLong.implementation = function (key: any, value: any) {
                var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.put, Type.long, key, null, value);
                        }
                    });
                }
                return this.putLong(key, value);
            };

            //putBoolean
            SharedPreferencesImpl_EditorImpl.putBoolean.implementation = function (key: any, value: any) {
                var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.put, Type.boolean, key, null, value);
                        }
                    });
                }
                return this.putBoolean(key, value);
            };

            //remove
            SharedPreferencesImpl_EditorImpl.remove.implementation = function (key: any) {
                var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

                if (targets) {
                    targets.forEach((target: any) => {
                        if (sharedPreferencesFile.toString().includes(target)) {
                            printData(target, Action.remove, Type.none, key, null, null);
                        }
                    });
                }
                return this.remove(key);
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