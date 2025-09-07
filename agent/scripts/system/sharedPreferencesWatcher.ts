import { Logger } from "../../utils/logger";
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
 * Perform hooks on the system watch shared preference files.
 */
export namespace SharedPreferencesWatcher {
    const NAME = "[SharedPreferencesWatcher]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    let targets: [string];

    export function initialize(targetList: [string]) {
        targets = targetList;
    }
    
    function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.app.SharedPreferencesImpl \x1b[0m`
            + `\n║ │ ├── contains`
            + `\n║ │ ├── getInt`
            + `\n║ │ ├── getFloat`
            + `\n║ │ ├── getLong`
            + `\n║ │ ├── getBoolean`
            + `\n║ │ ├── getString`
            + `\n║ │ └── getStringSet`
            + `\n║ └─┬\x1b[35m android.app.SharedPreferencesImpl$EditorImpl \x1b[0m`
            + `\n║   ├── putString`
            + `\n║   ├── putStringSet`
            + `\n║   ├── putInt`
            + `\n║   ├── putFloat`
            + `\n║   ├── putLong`
            + `\n║   ├── putBoolean`
            + `\n║   └── remove`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    export function performNow(): void {
        info()
        try {
            impl();
            editorImpl();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`);
        }
    }

    const SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    const SharedPreferencesImpl_EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    const File = Java.use("java.io.File");

    function impl() {
        SharedPreferencesImpl.contains.implementation = function (key: any) {
            var value = this.contains(key);
            var sharedPreferencesFile = Java.cast(this.mFile.value, Java.use("java.io.File"));

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.contains, Type.none, key, null, value);
                }
            });
            return value;
        };
        //getInt
        SharedPreferencesImpl.getInt.implementation = function (key: any, defValue: any) {
            var value = this.getInt(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.get, Type.int, key, defValue, value);
                }
            });
            return value;
        };
        //getFloat
        SharedPreferencesImpl.getFloat.implementation = function (key: any, defValue: any) {
            var value = this.getFloat(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.get, Type.float, key, defValue, value);
                }
            });
            return value;
        };
        //getLong
        SharedPreferencesImpl.getLong.implementation = function (key: any, defValue: any) {
            var value = this.getLong(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.get, Type.long, key, defValue, value);
                }
            });
            return value;
        };
        //getBoolean
        SharedPreferencesImpl.getBoolean.implementation = function (key: any, defValue: any) {
            var value = this.getBoolean(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.get, Type.boolean, key, defValue, value);
                }
            });
            return value;
        };
        //getString
        SharedPreferencesImpl.getString.implementation = function (key: any, defValue: any) {
            var value = this.getString(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.get, Type.string, key, defValue, value);
                }
            });
            return value;
        };
        //getStringSet
        SharedPreferencesImpl.getStringSet.implementation = function (key: any, defValue: any) {
            var value = this.getStringSet(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.get, Type.stringSet, key, defValue, value);
                }
            });
            return value;
        };
    }

    function editorImpl() {
        //putString
        SharedPreferencesImpl_EditorImpl.putString.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.put, Type.string, key, null, value);
                }
            });
            return this.putString(key, value);
        };
        //putStringSet
        SharedPreferencesImpl_EditorImpl.putStringSet.implementation = function (key: any, values: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.put, Type.stringSet, key, null, values);
                }
            });
            return this.putStringSet(key, values);
        };
        //putInt
        SharedPreferencesImpl_EditorImpl.putInt.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.put, Type.int, key, null, value);
                }
            });
            return this.putInt(key, value);
        };
        //putFloat
        SharedPreferencesImpl_EditorImpl.putFloat.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.put, Type.float, key, null, value);
                }
            });
            return this.putFloat(key, value);
        };
        //putLong
        SharedPreferencesImpl_EditorImpl.putLong.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.put, Type.long, key, null, value);
                }
            });
            return this.putLong(key, value);
        };
        //putBoolean
        SharedPreferencesImpl_EditorImpl.putBoolean.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.put, Type.boolean, key, null, value);
                }
            });
            return this.putBoolean(key, value);
        };
        //remove
        SharedPreferencesImpl_EditorImpl.remove.implementation = function (key: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);

            targets.forEach((target: any) => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    printData(target, Action.remove, Type.none, key, null, null);
                }
            });
            return this.remove(key);
        };
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

