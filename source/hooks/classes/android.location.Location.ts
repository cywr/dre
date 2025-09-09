import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.location.Location class to spoof location coordinates.
 */
export namespace Location {
    const NAME = "[Location]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    const spoofedLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        altitude: 10.0,
        accuracy: 5.0,
        provider: "gps"
    };

    export function perform(): void {
        try {
            const Location = Java.use("android.location.Location");

            // Hook getLatitude to return spoofed latitude
            Location.getLatitude.implementation = function () {
                const ret = this.getLatitude();
                log(`Location.getLatitude: ${ret} -> ${spoofedLocation.latitude}`);
                return spoofedLocation.latitude;
            };

            // Hook getLongitude to return spoofed longitude
            Location.getLongitude.implementation = function () {
                const ret = this.getLongitude();
                log(`Location.getLongitude: ${ret} -> ${spoofedLocation.longitude}`);
                return spoofedLocation.longitude;
            };

            // Hook getAltitude to return spoofed altitude
            Location.getAltitude.implementation = function () {
                const ret = this.getAltitude();
                log(`Location.getAltitude: ${ret} -> ${spoofedLocation.altitude}`);
                return spoofedLocation.altitude;
            };

            // Hook getAccuracy to return spoofed accuracy
            Location.getAccuracy.implementation = function () {
                const ret = this.getAccuracy();
                log(`Location.getAccuracy: ${ret} -> ${spoofedLocation.accuracy}`);
                return spoofedLocation.accuracy;
            };

            // Hook getProvider to return spoofed provider
            Location.getProvider.implementation = function () {
                const ret = this.getProvider();
                log(`Location.getProvider: ${ret} -> ${spoofedLocation.provider}`);
                return spoofedLocation.provider;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}