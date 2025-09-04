import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on resource-related classes to spoof system resources and content.
 */
export class Resources extends Hook {
    NAME = "[Resources]";
    LOG_TYPE = Logger.Type.Hook;

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.content.res.Resources \x1b[0m`
            + `\n║ │ ├── getConfiguration`
            + `\n║ │ ├── getDisplayMetrics`
            + `\n║ │ └── getString`
            + `\n║ ├─┬\x1b[35m android.content.res.ResourcesImpl \x1b[0m`
            + `\n║ │ └── getDisplayMetrics`
            + `\n║ ├─┬\x1b[35m android.content.ContentResolver \x1b[0m`
            + `\n║ │ └── query`
            + `\n║ └─┬\x1b[35m android.content.Context \x1b[0m`
            + `\n║   ├── getContentResolver`
            + `\n║   └── getPackageManager`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info();
        try {
            this.resourcesHooks();
            this.resourcesImplHooks();
            this.contentResolverHooks();
            this.contextHooks();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private Resources = Java.use("android.content.res.Resources");
    private ResourcesImpl = Java.use("android.content.res.ResourcesImpl");
    private ContentResolver = Java.use("android.content.ContentResolver");
    private Context = Java.use("android.content.Context");

    /**
     * Hooks Resources class to spoof system resources.
     */
    resourcesHooks() {
        const log = this.log;

        try {
            this.Resources.getConfiguration.implementation = function() {
                const ret = this.getConfiguration();
                
                // You could modify configuration here if needed
                // For example, screen size, locale, etc.
                log(`Resources.getConfiguration: accessed`);
                
                return ret;
            };

            this.Resources.getDisplayMetrics.implementation = function() {
                const ret = this.getDisplayMetrics();
                
                // Spoof display metrics to hide emulator characteristics
                // Common emulator resolutions: 1080x1920, 720x1280, etc.
                try {
                    // Samsung Galaxy S10 display metrics
                    ret.density.value = 3.0;
                    ret.densityDpi.value = 480; // DENSITY_XXHDPI
                    ret.widthPixels.value = 1440;
                    ret.heightPixels.value = 3040;
                    ret.scaledDensity.value = 3.0;
                    ret.xdpi.value = 480.0;
                    ret.ydpi.value = 480.0;
                    
                    log(`Resources.getDisplayMetrics: spoofed to Galaxy S10 metrics`);
                } catch (error) {
                    log(`Resources.getDisplayMetrics: failed to spoof metrics: ${error}`);
                }
                
                return ret;
            };

            this.Resources.getString.overload("int").implementation = function(id: number) {
                const ret = this.getString(id);
                
                // Monitor for specific strings that might reveal emulation
                if (ret && (ret.includes("emulator") || 
                           ret.includes("goldfish") || 
                           ret.includes("generic"))) {
                    log(`Resources.getString: potentially revealing string: ${ret}`);
                }
                
                return ret;
            };
        } catch (error) {
            log(`Resources hooks failed: ${error}`);
        }
    }

    /**
     * Hooks ResourcesImpl class (Android internal implementation).
     */
    resourcesImplHooks() {
        const log = this.log;

        try {
            this.ResourcesImpl.getDisplayMetrics.implementation = function() {
                const ret = this.getDisplayMetrics();
                
                // Spoof display metrics at the implementation level too
                try {
                    // Samsung Galaxy S10 display metrics
                    ret.density.value = 3.0;
                    ret.densityDpi.value = 480;
                    ret.widthPixels.value = 1440;
                    ret.heightPixels.value = 3040;
                    ret.scaledDensity.value = 3.0;
                    ret.xdpi.value = 480.0;
                    ret.ydpi.value = 480.0;
                    
                    log(`ResourcesImpl.getDisplayMetrics: spoofed to Galaxy S10 metrics`);
                } catch (error) {
                    log(`ResourcesImpl.getDisplayMetrics: failed to spoof metrics: ${error}`);
                }
                
                return ret;
            };
        } catch (error) {
            log(`ResourcesImpl hooks failed: ${error}`);
        }
    }

    /**
     * Hooks ContentResolver to monitor system content queries.
     */
    contentResolverHooks() {
        const log = this.log;

        try {
            this.ContentResolver.query.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    if (args.length > 0 && args[0]) {
                        try {
                            const uri = args[0].toString();
                            
                            // Monitor queries to system content providers
                            if (uri.includes("settings") || 
                                uri.includes("telephony") || 
                                uri.includes("device_info")) {
                                log(`ContentResolver.query: ${uri}`);
                            }
                        } catch (e) {
                            // URI might not be string-convertible
                        }
                    }
                    
                    const ret = this.query(...args);
                    
                    return ret;
                };
            });
        } catch (error) {
            log(`ContentResolver hooks failed: ${error}`);
        }
    }

    /**
     * Hooks Context class to monitor system service access.
     */
    contextHooks() {
        const log = this.log;

        try {
            this.Context.getContentResolver.implementation = function() {
                const ret = this.getContentResolver();
                log(`Context.getContentResolver: accessed`);
                return ret;
            };

            this.Context.getPackageManager.implementation = function() {
                const ret = this.getPackageManager();
                log(`Context.getPackageManager: accessed`);
                return ret;
            };
        } catch (error) {
            log(`Context hooks failed: ${error}`);
        }
    }
}