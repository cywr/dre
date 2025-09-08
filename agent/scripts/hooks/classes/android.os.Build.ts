import { Logger } from "../../../utils/logger";
import { DEFAULT_SPOOFED_DEVICE, DEFAULT_SPOOFED_VERSION } from "../../../utils/types";
import Java from "frida-java-bridge";

/**
 * Hook for android.os.Build class to spoof device build information and version details.
 */
export namespace Build {
    const NAME = "[Build]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const Build = Java.use("android.os.Build");
            const BuildVersion = Java.use("android.os.Build$VERSION");

            // Hook Build static fields
            for (const [key, value] of Object.entries(DEFAULT_SPOOFED_DEVICE)) {
                if (key === "ANDROID_ID" || key === "GSF_ID") continue; // These are handled elsewhere
                try {
                    Build[key].value = value;
                    log(`Build.${key} spoofed to: ${value}`);
                } catch (error) {
                    log(`Failed to spoof Build.${key}: ${error}`);
                }
            }

            // Hook VERSION static fields
            for (const [key, value] of Object.entries(DEFAULT_SPOOFED_VERSION)) {
                try {
                    BuildVersion[key].value = value;
                    log(`Build.VERSION.${key} spoofed to: ${value}`);
                } catch (error) {
                    log(`Failed to spoof Build.VERSION.${key}: ${error}`);
                }
            }

            // Hook Build methods
            Build.getRadioVersion.implementation = function () {
                const ret = this.getRadioVersion();
                log(`Build.getRadioVersion: ${ret} -> ${DEFAULT_SPOOFED_DEVICE.RADIO}`);
                return DEFAULT_SPOOFED_DEVICE.RADIO;
            };

            Build.getSerial.implementation = function () {
                const ret = this.getSerial();
                log(`Build.getSerial: ${ret} -> ${DEFAULT_SPOOFED_DEVICE.SERIAL}`);
                return DEFAULT_SPOOFED_DEVICE.SERIAL;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}