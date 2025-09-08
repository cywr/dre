import { Logger } from "../../utils/logger";
import { DEFAULT_SPOOFED_TELEPHONY } from "../../utils/types";
import Java from "frida-java-bridge";

/**
 * Hook for android.telephony.TelephonyManager class to spoof telephony and carrier information.
 */
export namespace TelephonyManager {
    const NAME = "[TelephonyManager]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const TelephonyManager = Java.use("android.telephony.TelephonyManager");
            const operator = DEFAULT_SPOOFED_TELEPHONY.mcc + DEFAULT_SPOOFED_TELEPHONY.mnc;

            // Network types
            TelephonyManager.getNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkType(...args);
                    log(`TelephonyManager.getNetworkType: ${ret} -> ${DEFAULT_SPOOFED_TELEPHONY.networkType}`);
                    return DEFAULT_SPOOFED_TELEPHONY.networkType;
                };
            });

            TelephonyManager.getDataNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getDataNetworkType(...args);
                    log(`TelephonyManager.getDataNetworkType: ${ret} -> ${DEFAULT_SPOOFED_TELEPHONY.dataNetworkType}`);
                    return DEFAULT_SPOOFED_TELEPHONY.dataNetworkType;
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
                    log(`TelephonyManager.getNetworkOperatorName: ${ret} -> ${DEFAULT_SPOOFED_TELEPHONY.operatorName}`);
                    return DEFAULT_SPOOFED_TELEPHONY.operatorName;
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
                    log(`TelephonyManager.getSimOperatorName: ${ret} -> ${DEFAULT_SPOOFED_TELEPHONY.operatorName}`);
                    return DEFAULT_SPOOFED_TELEPHONY.operatorName;
                };
            });

            TelephonyManager.getNetworkCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkCountryIso(...args);
                    log(`TelephonyManager.getNetworkCountryIso: ${ret} -> ${DEFAULT_SPOOFED_TELEPHONY.countryIso}`);
                    return DEFAULT_SPOOFED_TELEPHONY.countryIso;
                };
            });

            TelephonyManager.getSimCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getSimCountryIso(...args);
                    log(`TelephonyManager.getSimCountryIso: ${ret} -> ${DEFAULT_SPOOFED_TELEPHONY.countryIso}`);
                    return DEFAULT_SPOOFED_TELEPHONY.countryIso;
                };
            });

            // SIM State
            TelephonyManager.getSimState.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getSimState(...args);
                    log(`TelephonyManager.getSimState: ${ret} -> ${DEFAULT_SPOOFED_TELEPHONY.simState}`);
                    return DEFAULT_SPOOFED_TELEPHONY.simState;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}