import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.media.MediaDrm class to spoof DRM properties.
 */
export namespace AndroidMediaMediaDrm {
    const NAME = "[MediaDrm]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const MediaDrm = Java.use("android.media.MediaDrm");

            // Hook getPropertyString to return spoofed DRM properties
            MediaDrm.getPropertyString.implementation = function (propertyName: string) {
                const ret = this.getPropertyString(propertyName);

                switch (propertyName) {
                    case "vendor":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> Samsung`);
                        return "Samsung";
                    case "version":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> 1.4`);
                        return "1.4";
                    case "description":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> Samsung Exynos DRM`);
                        return "Samsung Exynos DRM";
                    case "deviceUniqueId":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> 0123456789abcdef`);
                        return "0123456789abcdef";
                    default:
                        return ret;
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}