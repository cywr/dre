import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.hardware.Sensor class to clean up emulator-specific sensor information.
 */
export namespace AndroidHardwareSensor {
    const NAME = "[Sensor]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const Sensor = Java.use("android.hardware.Sensor");

            // Hook getName to clean up emulator-specific sensor names
            Sensor.getName.implementation = function () {
                const ret = this.getName();
                if (ret.includes("Goldfish")) {
                    const spoofed = ret.replace("Goldfish ", "");
                    log(`Sensor.getName: ${ret} -> ${spoofed}`);
                    return spoofed;
                }
                return ret;
            };

            // Hook getVendor to clean up emulator-specific vendor names
            Sensor.getVendor.implementation = function () {
                const ret = this.getVendor();
                if (ret.includes("The Android Open Source Project") || ret.includes("AOSP")) {
                    const spoofed = ret.replace("The Android Open Source Project", "Sensors Inc.")
                        .replace("AOSP", "Sensors Inc.");
                    log(`Sensor.getVendor: ${ret} -> ${spoofed}`);
                    return spoofed;
                }
                return ret;
            };

            // Hook toString to clean up sensor descriptions
            (Sensor.toString as any).implementation = function () {
                const ret = this.toString();
                if (ret.includes("Goldfish") || ret.includes("The Android Open Source Project") || ret.includes("AOSP")) {
                    const spoofed = ret.replace(/Goldfish /g, "")
                        .replace(/The Android Open Source Project/g, "Sensors Inc.")
                        .replace(/AOSP/g, "Sensors Inc.");
                    log(`Sensor.toString: cleaned up sensor description`);
                    return spoofed;
                }
                return ret;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}