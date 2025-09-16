import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for Dynamic Class Loading (DCL) to monitor DexClassLoader, PathClassLoader, 
 * and other class loaders to watch classes and methods being loaded and invoked.
 */
export namespace DCL {
    const NAME = "[DCL]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function perform(): void {
        try {
            hookDexClassLoader();
            hookPathClassLoader();
            hookInMemoryDexClassLoader();
            hookBaseDexClassLoader();
        } catch(error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: ${error}`);
        }
    }

    function hookDexClassLoader() {
        try {
            const DexClassLoader = Java.use('dalvik.system.DexClassLoader');

            DexClassLoader.loadClass.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const className = args[0];
                    log(`DexClassLoader.loadClass: ${className}`);
                    const result = this.loadClass(...args);
                    
                    if (result && className) {
                        hookLoadedClass(result, className);
                    }
                    
                    return result;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `DexClassLoader hook failed: ${error}`);
        }
    }

    function hookPathClassLoader() {
        try {
            const PathClassLoader = Java.use('dalvik.system.PathClassLoader');

            PathClassLoader.loadClass.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const className = args[0];
                    log(`PathClassLoader.loadClass: ${className}`);
                    const result = this.loadClass(...args);
                    
                    if (result && className) {
                        hookLoadedClass(result, className);
                    }
                    
                    return result;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `PathClassLoader hook failed: ${error}`);
        }
    }

    function hookInMemoryDexClassLoader() {
        try {
            const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');

            InMemoryDexClassLoader.loadClass.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const className = args[0];
                    log(`InMemoryDexClassLoader.loadClass: ${className}`);
                    const result = this.loadClass(...args);
                    
                    if (result && className) {
                        hookLoadedClass(result, className);
                    }
                    
                    return result;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `InMemoryDexClassLoader hook failed: ${error}`);
        }
    }

    function hookBaseDexClassLoader() {
        try {
            const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
            
            BaseDexClassLoader.findClass.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const className = args[0];
                    log(`BaseDexClassLoader.findClass: ${className}`);
                    const result = this.findClass(...args);
                    
                    if (result && className) {
                        hookLoadedClass(result, className);
                    }
                    
                    return result;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `BaseDexClassLoader hook failed: ${error}`);
        }
    }

    function hookLoadedClass(clazz: any, className: string) {
        try {
            // Skip system classes to reduce noise
            if (className.startsWith('java.') || 
                className.startsWith('android.') || 
                className.startsWith('androidx.') ||
                className.startsWith('dalvik.') ||
                className.startsWith('com.android.')) {
                return;
            }

            const javaClass = Java.cast(clazz, Java.use('java.lang.Class'));
            const methods = javaClass.getDeclaredMethods();
            
            log(`Loaded class: ${className} with ${methods.length} methods`);
            
            // Hook methods of the dynamically loaded class
            Java.scheduleOnMainThread(() => {
                try {
                    const hookedClass = Java.use(className);
                    
                    // Get all method names
                    const methodNames = new Set<string>();
                    methods.forEach((method: any) => {
                        methodNames.add(method.getName());
                    });
                    
                    // Hook each unique method name
                    methodNames.forEach((methodName: string) => {
                        try {
                            if (hookedClass[methodName] && hookedClass[methodName].overloads) {
                                hookedClass[methodName].overloads.forEach((overload: any) => {
                                    overload.implementation = function(...args: any) {
                                        log(`Method invoked: ${className}.${methodName}(${args.length} args)`);
                                        return this[methodName](...args);
                                    };
                                });
                            }
                        } catch (methodError) {
                            Logger.log(Logger.Type.Debug, NAME, `Failed to hook method ${className}.${methodName}: ${methodError}`);
                        }
                    });
                } catch (hookError) {
                    Logger.log(Logger.Type.Debug, NAME, `Failed to hook class ${className}: ${hookError}`);
                }
            });
        } catch (error) {
            Logger.log(Logger.Type.Debug, NAME, `Failed to process loaded class ${className}: ${error}`);
        }
    }
}