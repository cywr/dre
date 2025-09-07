import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.telephony.TelephonyManager class to spoof telephony information.
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

            // Hook getNetworkType for all overloads
            TelephonyManager.getNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkType(...args);
                    log(`TelephonyManager.getNetworkType: ${ret} -> ${spoofedTelephony.networkType}`);
                    return spoofedTelephony.networkType;
                };
            });

            // Hook getNetworkOperator for all overloads
            TelephonyManager.getNetworkOperator.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkOperator(...args);
                    log(`TelephonyManager.getNetworkOperator: ${ret} -> ${operator}`);
                    return operator;
                };
            });

            // Hook getNetworkOperatorName for all overloads
            TelephonyManager.getNetworkOperatorName.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkOperatorName(...args);
                    log(`TelephonyManager.getNetworkOperatorName: ${ret} -> ${spoofedTelephony.operatorName}`);
                    return spoofedTelephony.operatorName;
                };
            });

            // Hook getNetworkCountryIso for all overloads
            TelephonyManager.getNetworkCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkCountryIso(...args);
                    log(`TelephonyManager.getNetworkCountryIso: ${ret} -> ${spoofedTelephony.countryIso}`);
                    return spoofedTelephony.countryIso;
                };
            });

            // Hook getSimCountryIso for all overloads
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