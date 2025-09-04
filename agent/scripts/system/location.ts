import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on location and sensor classes to bypass anti-emulation validations.
 */
export class Location extends Hook {
    NAME = "[Location & Sensor]";
    LOG_TYPE = Logger.Type.Hook;

    // Spoofed location coordinates (New York City)
    private spoofedLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        altitude: 10.0,
        accuracy: 5.0,
        provider: "gps"
    };

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.location.LocationManager \x1b[0m`
            + `\n║ │ └── isProviderEnabled`
            + `\n║ ├─┬\x1b[35m android.location.Location \x1b[0m`
            + `\n║ │ ├── getLatitude`
            + `\n║ │ ├── getLongitude`
            + `\n║ │ ├── getAltitude`
            + `\n║ │ ├── getAccuracy`
            + `\n║ │ └── getProvider`
            + `\n║ ├─┬\x1b[35m android.hardware.SensorManager \x1b[0m`
            + `\n║ │ └── getSensorList`
            + `\n║ └─┬\x1b[35m android.hardware.Sensor \x1b[0m`
            + `\n║   ├── getName`
            + `\n║   ├── getVendor`
            + `\n║   └── toString`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info();
        try {
            this.locationManagerHooks();
            this.locationHooks();
            this.sensorManagerHooks();
            this.sensorHooks();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private LocationManager = Java.use("android.location.LocationManager");
    private Location = Java.use("android.location.Location");
    private SensorManager = Java.use("android.hardware.SensorManager");
    private Sensor = Java.use("android.hardware.Sensor");

    /**
     * Hooks LocationManager to bypass location provider detection.
     */
    locationManagerHooks() {
        const log = this.log;

        try {
            this.LocationManager.isProviderEnabled.overload("java.lang.String").implementation = function(provider: string) {
                const ret = this.isProviderEnabled(provider);

                switch (provider) {
                    case "gps":
                    case "network":
                    case "passive":
                        log(`LocationManager.isProviderEnabled: ${provider} -> true`);
                        return true;
                    default:
                        log(`LocationManager.isProviderEnabled: ${provider} -> ${ret}`);
                        return ret;
                }
            };
        } catch (error) {
            log(`LocationManager hooks failed: ${error}`);
        }
    }

    /**
     * Hooks Location class to spoof GPS coordinates.
     */
    locationHooks() {
        const log = this.log;

        try {
            this.Location.getLatitude.implementation = function() {
                const ret = this.getLatitude();
                log(`Location.getLatitude: ${ret} -> ${this.spoofedLocation.latitude}`);
                return this.spoofedLocation.latitude;
            };

            this.Location.getLongitude.implementation = function() {
                const ret = this.getLongitude();
                log(`Location.getLongitude: ${ret} -> ${this.spoofedLocation.longitude}`);
                return this.spoofedLocation.longitude;
            };

            this.Location.getAltitude.implementation = function() {
                const ret = this.getAltitude();
                log(`Location.getAltitude: ${ret} -> ${this.spoofedLocation.altitude}`);
                return this.spoofedLocation.altitude;
            };

            this.Location.getAccuracy.implementation = function() {
                const ret = this.getAccuracy();
                log(`Location.getAccuracy: ${ret} -> ${this.spoofedLocation.accuracy}`);
                return this.spoofedLocation.accuracy;
            };

            this.Location.getProvider.implementation = function() {
                const ret = this.getProvider();
                log(`Location.getProvider: ${ret} -> ${this.spoofedLocation.provider}`);
                return this.spoofedLocation.provider;
            };
        } catch (error) {
            log(`Location hooks failed: ${error}`);
        }
    }

    /**
     * Hooks SensorManager to bypass sensor detection on older Android versions.
     */
    sensorManagerHooks() {
        const log = this.log;

        try {
            // This is primarily for older Android versions
            this.SensorManager.getSensorList.overload("int").implementation = function(type: number) {
                const ret = this.getSensorList(type);
                
                // Don't interfere with the sensor list unless absolutely necessary
                // Just log the call for awareness
                log(`SensorManager.getSensorList: type ${type}, count: ${ret.size()}`);
                
                return ret;
            };
        } catch (error) {
            log(`SensorManager hooks failed: ${error}`);
        }
    }

    /**
     * Hooks Sensor class to bypass emulator-specific sensor names.
     */
    sensorHooks() {
        const log = this.log;

        try {
            this.Sensor.getName.implementation = function() {
                const ret = this.getName();
                
                // Replace emulator-specific names
                if (ret.includes("Goldfish")) {
                    const spoofed = ret.replace("Goldfish ", "");
                    log(`Sensor.getName: ${ret} -> ${spoofed}`);
                    return spoofed;
                }
                
                return ret;
            };

            this.Sensor.getVendor.implementation = function() {
                const ret = this.getVendor();
                
                // Replace emulator-specific vendors
                if (ret.includes("The Android Open Source Project") || ret.includes("AOSP")) {
                    const spoofed = ret.replace("The Android Open Source Project", "Sensors Inc.")
                                      .replace("AOSP", "Sensors Inc.");
                    log(`Sensor.getVendor: ${ret} -> ${spoofed}`);
                    return spoofed;
                }
                
                return ret;
            };

            (this.Sensor.toString as any).implementation = function() {
                const ret = this.toString();
                
                // Clean up toString output
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
            log(`Sensor hooks failed: ${error}`);
        }
    }
}