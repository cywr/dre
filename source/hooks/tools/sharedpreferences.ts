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
 * Unified SharedPreferences monitoring hook for tracking both read and write operations.
 */
export namespace SharedPreferences {
    const NAME = "[SharedPreferences]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    let targets: string[] = [];

    /**
     * Logs general information about the SharedPreferences hook.
     */
    export function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m SharedPreferences Monitor \x1b[0m`
            + `\n║ ├── Read Operations (contains, get*)`
            + `\n║ ├── Write Operations (put*, remove)`
            + `\n║ └── Filtering by target files`
            + `\n╙─────────────────────────────────────────────────────┘`
        );
    }

    /**
     * Initialize the hook with optional target files to monitor.
     * @param targetList Optional list of specific SharedPreferences files to monitor
     */
    export function initialize(targetList?: string[]): void {
        targets = targetList || [];
    }

    /**
     * Main hook method that enables SharedPreferences monitoring.
     * @param targetList Optional list of specific SharedPreferences files to monitor
     */
    export function perform(targetList?: string[]): void {
        if (targetList) {
            initialize(targetList);
        }
        info();
        
        try {
            hookSharedPreferencesImpl();
            hookSharedPreferencesEditor();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Hook SharedPreferencesImpl for read operations.
     */
    function hookSharedPreferencesImpl(): void {
        const SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
        const File = Java.use("java.io.File");

        SharedPreferencesImpl.contains.implementation = function (key: any) {
            var value = this.contains(key);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.contains, Type.none, key, null, value);
            }
            return value;
        };

        SharedPreferencesImpl.getInt.implementation = function (key: any, defValue: any) {
            var value = this.getInt(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.get, Type.int, key, defValue, value);
            }
            return value;
        };

        SharedPreferencesImpl.getFloat.implementation = function (key: any, defValue: any) {
            var value = this.getFloat(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.get, Type.float, key, defValue, value);
            }
            return value;
        };

        SharedPreferencesImpl.getLong.implementation = function (key: any, defValue: any) {
            var value = this.getLong(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.get, Type.long, key, defValue, value);
            }
            return value;
        };

        SharedPreferencesImpl.getBoolean.implementation = function (key: any, defValue: any) {
            var value = this.getBoolean(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.get, Type.boolean, key, defValue, value);
            }
            return value;
        };

        SharedPreferencesImpl.getString.implementation = function (key: any, defValue: any) {
            var value = this.getString(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.get, Type.string, key, defValue, value);
            }
            return value;
        };

        SharedPreferencesImpl.getStringSet.implementation = function (key: any, defValue: any) {
            var value = this.getStringSet(key, defValue);
            var sharedPreferencesFile = Java.cast(this.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.get, Type.stringSet, key, defValue, value);
            }
            return value;
        };
    }

    /**
     * Hook SharedPreferencesImpl$EditorImpl for write operations.
     */
    function hookSharedPreferencesEditor(): void {
        const SharedPreferencesImpl_EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        const File = Java.use("java.io.File");

        SharedPreferencesImpl_EditorImpl.putString.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.put, Type.string, key, null, value);
            }
            return this.putString(key, value);
        };

        SharedPreferencesImpl_EditorImpl.putStringSet.implementation = function (key: any, values: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.put, Type.stringSet, key, null, values);
            }
            return this.putStringSet(key, values);
        };

        SharedPreferencesImpl_EditorImpl.putInt.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.put, Type.int, key, null, value);
            }
            return this.putInt(key, value);
        };

        SharedPreferencesImpl_EditorImpl.putFloat.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.put, Type.float, key, null, value);
            }
            return this.putFloat(key, value);
        };

        SharedPreferencesImpl_EditorImpl.putLong.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.put, Type.long, key, null, value);
            }
            return this.putLong(key, value);
        };

        SharedPreferencesImpl_EditorImpl.putBoolean.implementation = function (key: any, value: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.put, Type.boolean, key, null, value);
            }
            return this.putBoolean(key, value);
        };

        SharedPreferencesImpl_EditorImpl.remove.implementation = function (key: any) {
            var sharedPreferencesFile = Java.cast(this.this$0.value.mFile.value, File);
            
            if (shouldMonitor(sharedPreferencesFile.toString())) {
                printData(sharedPreferencesFile.toString(), Action.remove, Type.none, key, null, null);
            }
            return this.remove(key);
        };
    }

    /**
     * Check if a SharedPreferences file should be monitored based on target filters.
     */
    function shouldMonitor(filePath: string): boolean {
        if (targets.length === 0) {
            return true;
        }
        return targets.some(target => filePath.includes(target));
    }

    /**
     * Format and log SharedPreferences operation data.
     */
    function printData(target: string, action: Action, type: Type, key: any, defValue: any, value: any): void {
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