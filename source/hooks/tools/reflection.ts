import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Intercepts Java reflection API calls to monitor indirect class and method invocations
 * Hooks into Class.forName, Method.invoke, Constructor.newInstance, and Field access operations
 */
export namespace Reflection {
    const NAME = "[Reflection]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    // Filter out system/framework classes to avoid crashes
    const FILTERED_PACKAGES = [
        'java.lang.',
        'java.util.',
        'android.os.',
        'android.app.',
        'android.content.',
        'android.view.',
        'com.android.',
        'androidx.',
        'dalvik.',
        'libcore.',
        'sun.',
        'javax.crypto.'
    ];

    function shouldFilter(className: string): boolean {
        return FILTERED_PACKAGES.some(pkg => className.startsWith(pkg));
    }

    export function perform(): void {
        try {
            hookMethodInvoke();
            hookConstructorNewInstance();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: ${error}`);
        }
    }

    /**
     * Hooks Constructor.newInstance() to monitor reflective object instantiation
     */
    function hookConstructorNewInstance() {
        try {
            const constructorClass = Java.use('java.lang.reflect.Constructor');
            
            constructorClass.newInstance.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    try {
                        const declaringClass = this.getDeclaringClass().getName();
                        if (declaringClass && !shouldFilter(declaringClass)) {
                            log(`Constructor.newInstance() - ${declaringClass}`);
                        }
                    } catch (error) {}
                    
                    return this.newInstance(...args);
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Failed to hook Constructor.newInstance: ${error}`);
        }
    }

        /**
     * Hooks Method.invoke() to monitor reflective method calls
     */
    function hookMethodInvoke() {
        try {
            const methodClass = Java.use('java.lang.reflect.Method');
            
            methodClass.invoke.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    try {
                        const declaringClass = this.getDeclaringClass().getName();
                        if (declaringClass && !shouldFilter(declaringClass)) {
                            const methodName = this.getName();
                            log(`Method.invoke() - ${declaringClass}.${methodName}()`);
                        }
                    } catch (error) {}
                    
                    return this.invoke(...args);
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Failed to hook Method.invoke: ${error}`);
        }
    }
}