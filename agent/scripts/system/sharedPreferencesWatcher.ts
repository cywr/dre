import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";

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
export class SharedPreferencesWatcher implements Hook {
    NAME = "[SharedPreferencesWatcher]";
    LOG_TYPE = Logger.Type.Hook;

    targets!: [string];

    constructor(targets: [string]) {
        this.targets = targets;
    }
    
    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
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

    execute(): void {
        this.info()
        try {
            this.impl(this);
            this.editorImpl(this);
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    /** Hooked classes */
    _SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    _SharedPreferencesImpl_EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

    _File = Java.use("java.io.File");

    impl(_this: SharedPreferencesWatcher) {
        //Contains
        _this._SharedPreferencesImpl.contains.implementation = function (key: any) {
            var value = this.contains(key);
            var sharedPreferencesFile = Java.cast(this.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.contains, Type.none, key, null, value);
                }
            });
            return value;
        };
        //getInt
        _this._SharedPreferencesImpl.getInt.implementation = function (key: any, defValue: any) {
            var value = this.getInt(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.get, Type.int, key, defValue, value);
                }
            });
            return value;
        };
        //getFloat
        _this._SharedPreferencesImpl.getFloat.implementation = function (key: any, defValue: any) {
            var value = this.getFloat(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.get, Type.float, key, defValue, value);
                }
            });
            return value;
        };
        //getLong
        _this._SharedPreferencesImpl.getLong.implementation = function (key: any, defValue: any) {
            var value = this.getLong(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.get, Type.long, key, defValue, value);
                }
            });
            return value;
        };
        //getBoolean
        _this._SharedPreferencesImpl.getBoolean.implementation = function (key: any, defValue: any) {
            var value = this.getBoolean(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.get, Type.boolean, key, defValue, value);
                }
            });
            return value;
        };
        //getString
        _this._SharedPreferencesImpl.getString.implementation = function (key: any, defValue: any) {
            var value = this.getString(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.get, Type.string, key, defValue, value);
                }
            });
            return value;
        };
        //getStringSet
        _this._SharedPreferencesImpl.getStringSet.implementation = function (key: any, defValue: any) {
            var value = this.getStringSet(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.get, Type.stringSet, key, defValue, value);
                }
            });
            return value;
        };
    }

    editorImpl(_this: SharedPreferencesWatcher) {
        //putString
        _this._SharedPreferencesImpl_EditorImpl.putString.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.put, Type.string, key, null, value);
                }
            });
            return this.putString(key, value);
        };
        //putStringSet
        _this._SharedPreferencesImpl_EditorImpl.putStringSet.implementation = function (key: any, values: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.put, Type.stringSet, key, null, values);
                }
            });
            return this.putStringSet(key, values);
        };
        //putInt
        _this._SharedPreferencesImpl_EditorImpl.putInt.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.put, Type.int, key, null, value);
                }
            });
            return this.putInt(key, value);
        };
        //putFloat
        _this._SharedPreferencesImpl_EditorImpl.putFloat.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.put, Type.float, key, null, value);
                }
            });
            return this.putFloat(key, value);
        };
        //putLong
        _this._SharedPreferencesImpl_EditorImpl.putLong.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.put, Type.long, key, null, value);
                }
            });
            return this.putLong(key, value);
        };
        //putBoolean
        _this._SharedPreferencesImpl_EditorImpl.putBoolean.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.put, Type.boolean, key, null, value);
                }
            });
            return this.putBoolean(key, value);
        };
        //remove
        _this._SharedPreferencesImpl_EditorImpl.remove.implementation = function (key: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, _this._File);

            _this.targets.forEach(target => {
                if (sharedPreferencesFile.toString().includes(target)) {
                    _this.printData(target, Action.remove, Type.none, key, null, null);
                }
            });
            return this.remove(key);
        };
    }

    printData(target: string, action: Action, type: Type, key: any, defValue: any, value: any) {
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

        Logger.log(this.LOG_TYPE, this.NAME, message);
    }
}

