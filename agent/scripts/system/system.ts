import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on system-related classes to spoof device information and bypass detection.
 */
export class System extends Hook {
    NAME = "[System]";
    LOG_TYPE = Logger.Type.Hook;

    // Spoofed device properties
    private spoofedDevice = {
        BRAND: "samsung",
        MODEL: "SM-G975F",
        MANUFACTURER: "samsung",
        PRODUCT: "beyond2ltexx",
        DEVICE: "beyond2lte",
        BOARD: "exynos9820",
        HARDWARE: "exynos9820",
        FINGERPRINT: "samsung/beyond2ltexx/beyond2lte:11/RP1A.200720.012/G975FXXU8DUG1:user/release-keys",
        SERIAL: "RF8M802WZ8X",
        RADIO: "G975FXXU8DUG1"
    };

    private spoofedVersion = {
        RELEASE: "11",
        SDK_INT: 30,
        CODENAME: "REL",
        INCREMENTAL: "G975FXXU8DUG1",
        SECURITY_PATCH: "2021-07-01"
    };

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.os.Build \x1b[0m`
            + `\n║ │ ├── getRadioVersion`
            + `\n║ │ ├── getSerial`
            + `\n║ │ └── [Static Fields]`
            + `\n║ ├─┬\x1b[35m java.lang.System \x1b[0m`
            + `\n║ │ └── getProperty`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info();
        try {
            this.buildHooks();
            this.systemHooks();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private Build = Java.use("android.os.Build");
    private BuildVersion = Java.use("android.os.Build$VERSION");
    private SystemClass = Java.use("java.lang.System");

    /**
     * Hooks Build class to spoof device hardware information.
     */
    buildHooks() {
        const log = this.log;

        try {
            // Hook static fields
            for (const [key, value] of Object.entries(this.spoofedDevice)) {
                try {
                    this.Build[key].value = value;
                    log(`Build.${key} spoofed to: ${value}`);
                } catch (error) {
                    log(`Failed to spoof Build.${key}: ${error}`);
                }
            }

            // Hook VERSION static fields
            for (const [key, value] of Object.entries(this.spoofedVersion)) {
                try {
                    this.BuildVersion[key].value = value;
                    log(`Build.VERSION.${key} spoofed to: ${value}`);
                } catch (error) {
                    log(`Failed to spoof Build.VERSION.${key}: ${error}`);
                }
            }

            // Hook getRadioVersion method
            this.Build.getRadioVersion.implementation = function() {
                const ret = this.getRadioVersion();
                const spoofed = this.spoofedDevice.RADIO;
                log(`Build.getRadioVersion: ${ret} -> ${spoofed}`);
                return spoofed;
            };

            // Hook getSerial method
            this.Build.getSerial.implementation = function() {
                const ret = this.getSerial();
                const spoofed = this.spoofedDevice.SERIAL;
                log(`Build.getSerial: ${ret} -> ${spoofed}`);
                return spoofed;
            };
        } catch (error) {
            log(`Build hooks failed: ${error}`);
        }
    }

    /**
     * Hooks System.getProperty to spoof system properties.
     */
    systemHooks() {
        const log = this.log;

        try {
            this.SystemClass.getProperty.overload("java.lang.String").implementation = function(key: string) {
                const ret = this.getProperty(key);

                switch (key) {
                    case "ro.build.fingerprint":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.FINGERPRINT}`);
                        return this.spoofedDevice.FINGERPRINT;
                    case "ro.build.version.release":
                        log(`System.getProperty: ${key} -> ${this.spoofedVersion.RELEASE}`);
                        return this.spoofedVersion.RELEASE;
                    case "ro.product.model":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.MODEL}`);
                        return this.spoofedDevice.MODEL;
                    case "ro.product.brand":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.BRAND}`);
                        return this.spoofedDevice.BRAND;
                    case "ro.product.manufacturer":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.MANUFACTURER}`);
                        return this.spoofedDevice.MANUFACTURER;
                    case "ro.hardware":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.HARDWARE}`);
                        return this.spoofedDevice.HARDWARE;
                    default:
                        return ret;
                }
            };

            this.SystemClass.getProperty.overload("java.lang.String", "java.lang.String").implementation = function(key: string, defaultValue: string) {
                const ret = this.getProperty(key, defaultValue);

                switch (key) {
                    case "ro.build.fingerprint":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.FINGERPRINT}`);
                        return this.spoofedDevice.FINGERPRINT;
                    case "ro.build.version.release":
                        log(`System.getProperty: ${key} -> ${this.spoofedVersion.RELEASE}`);
                        return this.spoofedVersion.RELEASE;
                    case "ro.product.model":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.MODEL}`);
                        return this.spoofedDevice.MODEL;
                    case "ro.product.brand":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.BRAND}`);
                        return this.spoofedDevice.BRAND;
                    case "ro.product.manufacturer":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.MANUFACTURER}`);
                        return this.spoofedDevice.MANUFACTURER;
                    case "ro.hardware":
                        log(`System.getProperty: ${key} -> ${this.spoofedDevice.HARDWARE}`);
                        return this.spoofedDevice.HARDWARE;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            log(`System hooks failed: ${error}`);
        }
    }

}