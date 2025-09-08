import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.content.res.ResourcesImpl class to spoof implementation-level resources.
 */
export namespace ResourcesImpl {
    const NAME = "[ResourcesImpl]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const ResourcesImpl = Java.use("android.content.res.ResourcesImpl");

            // Hook getDisplayMetrics to spoof display metrics (Galaxy S10)
            ResourcesImpl.getDisplayMetrics.implementation = function () {
                const ret = this.getDisplayMetrics();
                try {
                    ret.density.value = 3.0;
                    ret.densityDpi.value = 480;
                    ret.widthPixels.value = 1440;
                    ret.heightPixels.value = 3040;
                    ret.scaledDensity.value = 3.0;
                    ret.xdpi.value = 480.0;
                    ret.ydpi.value = 480.0;
                    log(`ResourcesImpl.getDisplayMetrics: spoofed to Galaxy S10 metrics`);
                } catch (error) {
                    log(`Failed to spoof impl display metrics: ${error}`);
                }
                return ret;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}