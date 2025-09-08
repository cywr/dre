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
        networkType: 13, // LTE
        dataNetworkType: 13 // LTE
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

            TelephonyManager.getDataNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getDataNetworkType(...args);
                    log(`TelephonyManager.getDataNetworkType: ${ret} -> ${spoofedTelephony.dataNetworkType}`);
                    return spoofedTelephony.dataNetworkType;
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

            // SIM Operator methods
            TelephonyManager.getSimOperator.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getSimOperator(...args);
                    log(`TelephonyManager.getSimOperator: ${ret} -> ${operator}`);
                    return operator;
                };
            });

            TelephonyManager.getSimOperatorName.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getSimOperatorName(...args);
                    log(`TelephonyManager.getSimOperatorName: ${ret} -> ${spoofedTelephony.operatorName}`);
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

            // SIM State
            TelephonyManager.getSimState.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getSimState(...args);
                    log(`TelephonyManager.getSimState: ${ret} -> ${spoofedTelephony.simState}`);
                    return spoofedTelephony.simState;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}