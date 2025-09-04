import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on media and UI classes to bypass detection and monitoring.
 */
export class Media extends Hook {
    NAME = "[Media & UI]";
    LOG_TYPE = Logger.Type.Hook;

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.media.MediaDrm \x1b[0m`
            + `\n║ │ └── getPropertyString`
            + `\n║ ├─┬\x1b[35m android.webkit.WebView \x1b[0m`
            + `\n║ │ └── getUserAgentString`
            + `\n║ ├─┬\x1b[35m android.app.Activity \x1b[0m`
            + `\n║ │ └── startActivity`
            + `\n║ └─┬\x1b[35m android.content.Intent \x1b[0m`
            + `\n║   ├── getAction`
            + `\n║   ├── getStringExtra`
            + `\n║   └── putExtra`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info();
        try {
            this.mediaDrmHooks();
            this.webViewHooks();
            this.activityHooks();
            this.intentHooks();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private MediaDrm = Java.use("android.media.MediaDrm");
    private WebView = Java.use("android.webkit.WebView");
    private Activity = Java.use("android.app.Activity");
    private Intent = Java.use("android.content.Intent");

    /**
     * Hooks MediaDrm to spoof DRM-related device properties.
     */
    mediaDrmHooks() {
        const log = this.log;

        try {
            this.MediaDrm.getPropertyString.implementation = function(propertyName: string) {
                const ret = this.getPropertyString(propertyName);

                switch (propertyName) {
                    case "vendor":
                        const spoofedVendor = "Samsung";
                        log(`MediaDrm.getPropertyString: ${propertyName} -> ${spoofedVendor}`);
                        return spoofedVendor;
                    case "version":
                        const spoofedVersion = "1.4";
                        log(`MediaDrm.getPropertyString: ${propertyName} -> ${spoofedVersion}`);
                        return spoofedVersion;
                    case "description":
                        const spoofedDescription = "Samsung Exynos DRM";
                        log(`MediaDrm.getPropertyString: ${propertyName} -> ${spoofedDescription}`);
                        return spoofedDescription;
                    case "deviceUniqueId":
                        const spoofedId = "0123456789abcdef";
                        log(`MediaDrm.getPropertyString: ${propertyName} -> ${spoofedId}`);
                        return spoofedId;
                    default:
                        log(`MediaDrm.getPropertyString: ${propertyName} -> ${ret}`);
                        return ret;
                }
            };
        } catch (error) {
            log(`MediaDrm hooks failed: ${error}`);
        }
    }

    /**
     * Hooks WebView to spoof User-Agent strings.
     */
    webViewHooks() {
        const log = this.log;

        try {
            this.WebView.getUserAgentString.overload("android.content.Context").implementation = function(context: any) {
                const ret = this.getUserAgentString(context);
                
                // Check if User-Agent contains emulator signatures
                if (ret.includes("Android SDK built for x86") || 
                    ret.includes("Emulator") || 
                    ret.includes("generic")) {
                    
                    const spoofedUA = "Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36";
                    log(`WebView.getUserAgentString: spoofed emulator UA`);
                    return spoofedUA;
                }
                
                return ret;
            };

            // Hook instance method as well
            this.WebView.getUserAgentString.overload().implementation = function() {
                const ret = this.getUserAgentString();
                
                // Check if User-Agent contains emulator signatures
                if (ret.includes("Android SDK built for x86") || 
                    ret.includes("Emulator") || 
                    ret.includes("generic")) {
                    
                    const spoofedUA = "Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36";
                    log(`WebView.getUserAgentString: spoofed emulator UA`);
                    return spoofedUA;
                }
                
                return ret;
            };
        } catch (error) {
            log(`WebView hooks failed: ${error}`);
        }
    }

    /**
     * Hooks Activity to monitor app launches.
     */
    activityHooks() {
        const log = this.log;

        try {
            this.Activity.startActivity.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    if (args.length > 0 && args[0]) {
                        try {
                            const intent = args[0];
                            const action = intent.getAction ? intent.getAction() : "unknown";
                            log(`Activity.startActivity: ${action}`);
                        } catch (e) {
                            log(`Activity.startActivity: called`);
                        }
                    } else {
                        log(`Activity.startActivity: called`);
                    }
                    return this.startActivity(...args);
                };
            });
        } catch (error) {
            log(`Activity hooks failed: ${error}`);
        }
    }

    /**
     * Hooks Intent to monitor inter-app communications.
     */
    intentHooks() {
        const log = this.log;

        try {
            // Monitor common suspicious actions
            const suspiciousActions = [
                "android.intent.action.BATTERY_CHANGED",
                "android.intent.action.DEVICE_STORAGE_LOW",
                "android.intent.action.DEVICE_STORAGE_OK"
            ];

            this.Intent.getAction.implementation = function() {
                const ret = this.getAction();
                
                if (ret && suspiciousActions.includes(ret)) {
                    log(`Intent.getAction: ${ret}`);
                }
                
                return ret;
            };

            this.Intent.getStringExtra.implementation = function(name: string) {
                const ret = this.getStringExtra(name);
                
                // Monitor for specific extras that might reveal emulation
                if (name && (name.includes("battery") || 
                           name.includes("storage") || 
                           name.includes("device"))) {
                    log(`Intent.getStringExtra: ${name} -> ${ret}`);
                }
                
                return ret;
            };

            // Hook putExtra to potentially modify suspicious data
            this.Intent.putExtra.overload("java.lang.String", "java.lang.String").implementation = function(name: string, value: string) {
                // Log battery-related extras
                if (name && name.includes("battery") && value) {
                    log(`Intent.putExtra: ${name} -> ${value}`);
                }
                
                return this.putExtra(name, value);
            };
        } catch (error) {
            log(`Intent hooks failed: ${error}`);
        }
    }
}