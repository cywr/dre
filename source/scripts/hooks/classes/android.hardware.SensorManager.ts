import { Logger } from "../../../utils/logger";
import { SENSOR_VENDOR_REPLACEMENTS } from "../../../utils/enums";
import Java from "frida-java-bridge";

/**
 * Hook for android.hardware.SensorManager class to manage sensor detection and emulation bypass.
 */
export namespace SensorManager {
    const NAME = "[SensorManager]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);
    const verboseLog = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(sensors?: any): void {
        try {
            if (sensors) {
                antiEmulation(sensors);
            } else {
                // Default anti-emulation without custom sensors
                antiEmulation();
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Perform the hook of getSensorList and replace emulated sensors by real sensors.
     * In Android 10+, the getters from Sensors are hooked instead.
     */
    function antiEmulation(sensors?: any): void {
        const AndroidVersion = Java.use("android.os.Build$VERSION");
        
        if (AndroidVersion.SDK_INT.value > 30) {
            // Android 11+ solution
            try {
                const SensorManager = Java.use("android.hardware.SensorManager");
                const Sensor = Java.use("android.hardware.Sensor");
                const InputSensorInfo = Java.use("android.hardware.input.InputSensorInfo");

                try {
                    SensorManager.getSensorList.overload("int").implementation = function (type: any) {
                        log(`getSensorList(${type}) called`);

                        if (sensors && Array.isArray(sensors)) {
                            const ret = Java.use("java.util.ArrayList").$new();

                            for (let i = 0; i < sensors.length; i++) {
                                const sensor = sensors[i];

                                if (type === -1 || type === sensor.type) {
                                    verboseLog(`Setting up sensor: ${sensor.name}`);
                                    ret.add(Sensor.$new(InputSensorInfo.$new(
                                        sensor.name,
                                        sensor.vendor,
                                        sensor.version,
                                        0,
                                        sensor.type,
                                        sensor.maximumRange,
                                        sensor.resolution,
                                        sensor.power,
                                        sensor.minDelay,
                                        sensor.fifoReservedEventCount,
                                        sensor.fifoMaxEventCount,
                                        sensor.stringType,
                                        "",
                                        sensor.maxDelay,
                                        1,
                                        sensor.id,
                                    )));
                                }
                            }

                            return ret;
                        } else {
                            // Fall back to original implementation if no sensors provided
                            return this.getSensorList(type);
                        }
                    };
                } catch (error) {
                    Logger.log(Logger.Type.Error, NAME, `getSensorList hook failed: ${error}`);
                }
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `Android 11+ antiEmulation failed: ${error}`);
            }
        } else {
            // Android 10 and below solution
            try {
                const Sensor = Java.use("android.hardware.Sensor");

                try {
                    Sensor.getName.implementation = function () {
                        const name = this.getName();
                        let spoof = name;
                        
                        for (const [pattern, replacement] of Object.entries(SENSOR_VENDOR_REPLACEMENTS)) {
                            spoof = spoof.replace(new RegExp(pattern, 'g'), replacement);
                        }

                        log(`getName: ${name} -> ${spoof}`);
                        return spoof;
                    };
                } catch (error) {
                    Logger.log(Logger.Type.Error, NAME, `getName hook failed: ${error}`);
                }

                try {
                    (Sensor.toString as any).implementation = function () {
                        const name = this.toString();
                        let spoof = name;
                        
                        for (const [pattern, replacement] of Object.entries(SENSOR_VENDOR_REPLACEMENTS)) {
                            spoof = spoof.replace(new RegExp(pattern, 'g'), replacement);
                        }

                        log(`toString: ${name} -> ${spoof}`);
                        return spoof;
                    };
                } catch (error) {
                    Logger.log(Logger.Type.Error, NAME, `toString hook failed: ${error}`);
                }

                try {
                    Sensor.getVendor.implementation = function () {
                        const vendor = this.getVendor();
                        let spoof = vendor;
                        
                        for (const [pattern, replacement] of Object.entries(SENSOR_VENDOR_REPLACEMENTS)) {
                            if (pattern !== "Goldfish ") { // Skip Goldfish replacement for vendor
                                spoof = spoof.replace(new RegExp(pattern, 'g'), replacement);
                            }
                        }

                        log(`getVendor: ${vendor} -> ${spoof}`);
                        return spoof;
                    };
                } catch (error) {
                    Logger.log(Logger.Type.Error, NAME, `getVendor hook failed: ${error}`);
                }
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `Android 10- antiEmulation failed: ${error}`);
            }
        }
    }
}