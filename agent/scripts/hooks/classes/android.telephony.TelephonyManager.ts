import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.telephony.TelephonyManager class to spoof telephony and carrier information.
 */
export namespace AndroidTelephonyTelephonyManager {
    const NAME = "[TelephonyManager]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    const spoofedTelephony = {
        mcc: "310",
        mnc: "260",
        operatorName: "T-Mobile",
        countryIso: "us",
        simState: 5,
        networkType: 13
    };

    export function performNow(): void {
        try {
            const TelephonyManager = Java.use("android.telephony.TelephonyManager");
            const operator = spoofedTelephony.mcc + spoofedTelephony.mnc;

            // Network types
            TelephonyManager.getNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkType(...args);
                    log(`TelephonyManager.getNetworkType: ${ret} -> ${spoofedTelephony.networkType}`);
                    return spoofedTelephony.networkType;
                };
            });

            // Operators
            TelephonyManager.getNetworkOperator.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkOperator(...args);
                    log(`TelephonyManager.getNetworkOperator: ${ret} -> ${operator}`);
                    return operator;
                };
            });

            TelephonyManager.getNetworkOperatorName.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkOperatorName(...args);
                    log(`TelephonyManager.getNetworkOperatorName: ${ret} -> ${spoofedTelephony.operatorName}`);
                    return spoofedTelephony.operatorName;
                };
            });

            TelephonyManager.getNetworkCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkCountryIso(...args);
                    log(`TelephonyManager.getNetworkCountryIso: ${ret} -> ${spoofedTelephony.countryIso}`);
                    return spoofedTelephony.countryIso;
                };
            });

            TelephonyManager.getSimCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getSimCountryIso(...args);
                    log(`TelephonyManager.getSimCountryIso: ${ret} -> ${spoofedTelephony.countryIso}`);
                    return spoofedTelephony.countryIso;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}