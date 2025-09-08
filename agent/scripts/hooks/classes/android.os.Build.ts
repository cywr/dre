import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.os.Build class to spoof device build information and version details.
 */
export namespace AndroidOSBuild {
    const NAME = "[Build]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    // Spoofed device configuration
    const spoofedDevice = {
        BRAND: "samsung",
        MODEL: "SM-G975F",
        MANUFACTURER: "samsung",
        PRODUCT: "beyond2ltexx",
        DEVICE: "beyond2lte",
        BOARD: "exynos9820",
        HARDWARE: "exynos9820",
        FINGERPRINT: "samsung/beyond2ltexx/beyond2lte:11/RP1A.200720.012/G975FXXU8DUG1:user/release-keys",
        SERIAL: "RF8M802WZ8X",
        RADIO: "G975FXXU8DUG1",
        ANDROID_ID: "9774d56d682e549c",
        GSF_ID: "3f4c5e6d7a8b9c0d"
    };

    const spoofedVersion = {
        RELEASE: "11",
        SDK_INT: 30,
        CODENAME: "REL",
        INCREMENTAL: "G975FXXU8DUG1",
        SECURITY_PATCH: "2021-07-01"
    };

    export function performNow(): void {
        try {
            const Build = Java.use("android.os.Build");
            const BuildVersion = Java.use("android.os.Build$VERSION");

            // Hook Build static fields
            for (const [key, value] of Object.entries(spoofedDevice)) {
                if (key === "ANDROID_ID" || key === "GSF_ID") continue; // These are handled elsewhere
                try {
                    Build[key].value = value;
                    log(`Build.${key} spoofed to: ${value}`);
                } catch (error) {
                    log(`Failed to spoof Build.${key}: ${error}`);
                }
            }

            // Hook VERSION static fields
            for (const [key, value] of Object.entries(spoofedVersion)) {
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
                log(`Build.getRadioVersion: ${ret} -> ${spoofedDevice.RADIO}`);
                return spoofedDevice.RADIO;
            };

            Build.getSerial.implementation = function () {
                const ret = this.getSerial();
                log(`Build.getSerial: ${ret} -> ${spoofedDevice.SERIAL}`);
                return spoofedDevice.SERIAL;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}