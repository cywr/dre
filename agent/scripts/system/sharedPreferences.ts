import { Logger } from "../../utils/logger";

export namespace SharedPreferences {
    const NAME = "[SharedPreferences]";
    /**
     * Perform hooks on the system watch shared preference files.
     * 
     */

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

    export function hook(target: string) {
        Logger.log(Logger.Type.Config, NAME, "Hooks loaded.");
        try {
            impl(target);
            editorImpl(target);
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed.\n${error}`);
        }
    }

    function impl(target: string) {
        const sharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
        var file = Java.use("java.io.File");

        //Contains
        sharedPreferencesImpl.contains.implementation = function (key: any) {
            var value = this.contains(key);
            var sharedPreferencesFile = Java.cast(this.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.contains, Type.none, key, null, value);
            }
            return value;
        };
        //getInt
        sharedPreferencesImpl.getInt.implementation = function (key: any, defValue: any) {
            var value = this.getInt(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.get, Type.int, key, defValue, value);
            }
            return value;
        };
        //getFloat
        sharedPreferencesImpl.getFloat.implementation = function (key: any, defValue: any) {
            var value = this.getFloat(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.get, Type.float, key, defValue, value);
            }
            return value;
        };
        //getLong
        sharedPreferencesImpl.getLong.implementation = function (key: any, defValue: any) {
            var value = this.getLong(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.get, Type.long, key, defValue, value);
            }
            return value;
        };
        //getBoolean
        sharedPreferencesImpl.getBoolean.implementation = function (key: any, defValue: any) {
            var value = this.getBoolean(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.get, Type.boolean, key, defValue, value);
            }
            return value;
        };
        //getString
        sharedPreferencesImpl.getString.implementation = function (key: any, defValue: any) {
            var value = this.getString(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.get, Type.string, key, defValue, value);
            }
            return value;
        };
        //getStringSet
        sharedPreferencesImpl.getStringSet.implementation = function (key: any, defValue: any) {
            var value = this.getStringSet(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.get, Type.stringSet, key, defValue, value);
            }
            return value;
        };
    }

    function editorImpl(target: string) {
        var sharedPreferencesImpl_EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        var file = Java.use("java.io.File");

        //putString
        sharedPreferencesImpl_EditorImpl.putString.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.put, Type.string, key, null, value);
            }
            return this.putString(key, value);
        };
        //putStringSet
        sharedPreferencesImpl_EditorImpl.putStringSet.implementation = function (key: any, values: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.put, Type.stringSet, key, null, values);
            }
            return this.putStringSet(key, values);
        };
        //putInt
        sharedPreferencesImpl_EditorImpl.putInt.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.put, Type.int, key, null, value);
            }
            return this.putInt(key, value);
        };
        //putFloat
        sharedPreferencesImpl_EditorImpl.putFloat.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.put, Type.float, key, null, value);
            }
            return this.putFloat(key, value);
        };
        //putBoolean
        sharedPreferencesImpl_EditorImpl.putBoolean.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.put, Type.boolean, key, null, value);
            }
            return this.putBoolean(key, value);
        };
        //putLong
        sharedPreferencesImpl_EditorImpl.putLong.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.put, Type.long, key, null, value);
            }
            return this.putLong(key, value);
        };
        //remove
        sharedPreferencesImpl_EditorImpl.remove.implementation = function (key: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, file);

            if (sharedPreferencesFile.toString().includes(target)) {
                printData(target, Action.remove, Type.none, key, null, null);
            }
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

        Logger.log(Logger.Type.Hook, NAME, message);
    }

}

