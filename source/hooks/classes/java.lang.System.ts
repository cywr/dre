import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.lang.System class to manage system properties and library loading.
 */
export namespace System {
    const NAME = "[System]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);
    const verboseLog = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    // Basic device spoofing properties
    const spoofedProperties: Record<string, string> = {
        "os.arch": "aarch64",
        "os.name": "Linux",
        "java.vm.version": "2.1.0",
        "java.vm.name": "ART",
        "java.vm.vendor": "The Android Open Source Project",
        "java.specification.version": "0.9",
        "java.specification.name": "Dalvik Core Library",
        "java.specification.vendor": "The Android Open Source Project",
        "java.version": "0",
        "java.vendor": "The Android Open Source Project",
        "java.vendor.url": "http://www.android.com/",
        "java.class.version": "50.0",
        "java.class.path": "."
    };

    export function performNow(): void {
        try {
            antiEmulation();
            interceptNativeLibraries();
            interceptGetEnvironment();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Hook system properties to prevent emulation detection.
     */
    function antiEmulation(): void {
        try {
            const System = Java.use("java.lang.System");
            
            System.getProperty.overload("java.lang.String").implementation = function (name: string) {
                const spoofed = spoofedProperties[name];
                
                if (spoofed) {
                    log(`getProperty: ${name} -> ${spoofed}`);
                    return spoofed;
                }

                // Generate basic user agent for http.agent property
                if (name === "http.agent") {
                    const ua = "Dalvik/2.1.0 (Linux; U; Android 12; SM-G991B Build/SP1A.210812.016)";
                    log(`getProperty (UserAgent): ${name} -> ${ua}`);
                    return ua;
                }

                return this.getProperty.call(this, name);
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `antiEmulation failed: ${error}`);
        }
    }

    /**
     * Monitor native library loading.
     */
    function interceptNativeLibraries(): void {
        try {
            verboseLog("Hooking System.loadLibrary() overloads...");

            const System = Java.use("java.lang.System");
            const Runtime = Java.use("java.lang.Runtime");
            const VMStack = Java.use("dalvik.system.VMStack");
            const VERSION = Java.use("android.os.Build$VERSION");

            System.loadLibrary.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    log(`JNI loadLibrary: ${args[0]}`);
                    
                    try {
                        if (VERSION.SDK_INT.value >= 29) {
                            Runtime.getRuntime().loadLibrary0(Java.use("sun.reflect.Reflection").getCallerClass(), args[0]);
                        } else if (VERSION.SDK_INT.value >= 24) {
                            Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), args[0]);
                        } else {
                            Runtime.getRuntime().loadLibrary(args[0], VMStack.getCallingClassLoader());
                        }
                    } catch (error) {
                        log(`loadLibrary implementation error: ${error}`);
                        return this.loadLibrary(...args);
                    }
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `interceptNativeLibraries failed: ${error}`);
        }
    }

    /**
     * Hook environment variable access.
     */
    function interceptGetEnvironment(): void {
        try {
            const System = Java.use("java.lang.System");
            
            System.getenv.overload().implementation = function () {
                const ret = this.getenv();
                const Collections = Java.use("java.util.Collections");
                
                log("getenv: returning empty map for security");
                return Collections.emptyMap();
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `interceptGetEnvironment failed: ${error}`);
        }
    }
}