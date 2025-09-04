import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on TelephonyManager to bypass anti-emulation validations and spoof carrier information.
 */
export class Telephony extends Hook {
    NAME = "[Telephony]";
    LOG_TYPE = Logger.Type.Hook;

    private spoofedCarrier = {
        mcc: "310",
        mnc: "260",
        operatorName: "T-Mobile",
        countryIso: "us",
        simState: 5, // SIM_STATE_READY
        networkType: 13 // NETWORK_TYPE_LTE
    };

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └─┬\x1b[35m android.telephony.TelephonyManager \x1b[0m`
            + `\n║   ├── getNetworkType`
            + `\n║   ├── getDataNetworkType`
            + `\n║   ├── getNetworkOperator`
            + `\n║   ├── getSimOperator`
            + `\n║   ├── getNetworkOperatorName`
            + `\n║   ├── getSimOperatorName`
            + `\n║   ├── getNetworkCountryIso`
            + `\n║   ├── getSimCountryIso`
            + `\n║   ├── getSimState`
            + `\n║   ├── getDeviceId`
            + `\n║   ├── getImei`
            + `\n║   └── getMeid`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info();
        try {
            this.networkTypeHooks();
            this.carrierHooks();
            this.deviceIdHooks();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private TelephonyManager = Java.use("android.telephony.TelephonyManager");

    /**
     * Hooks network type methods to bypass emulation detection.
     */
    networkTypeHooks() {
        const log = this.log;

        try {
            this.TelephonyManager.getNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getNetworkType(...args);
                    log(`TelephonyManager.getNetworkType: ${ret} -> ${this.spoofedCarrier.networkType}`);
                    return this.spoofedCarrier.networkType;
                };
            });

            this.TelephonyManager.getDataNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getDataNetworkType(...args);
                    log(`TelephonyManager.getDataNetworkType: ${ret} -> ${this.spoofedCarrier.networkType}`);
                    return this.spoofedCarrier.networkType;
                };
            });
        } catch (error) {
            log(`Network type hooks failed: ${error}`);
        }
    }

    /**
     * Hooks carrier-related methods to spoof carrier information.
     */
    carrierHooks() {
        const log = this.log;
        const operator = this.spoofedCarrier.mcc + this.spoofedCarrier.mnc;

        try {
            // Network and SIM operator
            this.TelephonyManager.getNetworkOperator.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getNetworkOperator(...args);
                    log(`TelephonyManager.getNetworkOperator: ${ret} -> ${operator}`);
                    return operator;
                };
            });

            this.TelephonyManager.getSimOperator.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getSimOperator(...args);
                    log(`TelephonyManager.getSimOperator: ${ret} -> ${operator}`);
                    return operator;
                };
            });

            // Operator names
            this.TelephonyManager.getNetworkOperatorName.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getNetworkOperatorName(...args);
                    log(`TelephonyManager.getNetworkOperatorName: ${ret} -> ${this.spoofedCarrier.operatorName}`);
                    return this.spoofedCarrier.operatorName;
                };
            });

            this.TelephonyManager.getSimOperatorName.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getSimOperatorName(...args);
                    log(`TelephonyManager.getSimOperatorName: ${ret} -> ${this.spoofedCarrier.operatorName}`);
                    return this.spoofedCarrier.operatorName;
                };
            });

            // Country ISO codes
            this.TelephonyManager.getNetworkCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getNetworkCountryIso(...args);
                    log(`TelephonyManager.getNetworkCountryIso: ${ret} -> ${this.spoofedCarrier.countryIso}`);
                    return this.spoofedCarrier.countryIso;
                };
            });

            this.TelephonyManager.getSimCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getSimCountryIso(...args);
                    log(`TelephonyManager.getSimCountryIso: ${ret} -> ${this.spoofedCarrier.countryIso}`);
                    return this.spoofedCarrier.countryIso;
                };
            });

            // SIM state
            this.TelephonyManager.getSimState.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getSimState(...args);
                    log(`TelephonyManager.getSimState: ${ret} -> ${this.spoofedCarrier.simState}`);
                    return this.spoofedCarrier.simState;
                };
            });
        } catch (error) {
            log(`Carrier hooks failed: ${error}`);
        }
    }

    /**
     * Hooks device ID methods (commented out by default to avoid crashes).
     * Enable only when needed and with proper spoofed values.
     */
    deviceIdHooks() {
        const log = this.log;

        // Note: These hooks are commented out as they may cause crashes
        // Enable them only when you have proper spoofed device IDs
        
        try {
            /*
            this.TelephonyManager.getDeviceId.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getDeviceId(...args);
                    const spoofedDeviceId = "123456789012345";
                    log(`TelephonyManager.getDeviceId: ${ret} -> ${spoofedDeviceId}`);
                    return spoofedDeviceId;
                };
            });

            this.TelephonyManager.getImei.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getImei(...args);
                    const spoofedImei = "123456789012345";
                    log(`TelephonyManager.getImei: ${ret} -> ${spoofedImei}`);
                    return spoofedImei;
                };
            });

            this.TelephonyManager.getMeid.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    const ret = this.getMeid(...args);
                    const spoofedMeid = "12345678901234";
                    log(`TelephonyManager.getMeid: ${ret} -> ${spoofedMeid}`);
                    return spoofedMeid;
                };
            });
            */
            log(`Device ID hooks are disabled by default to prevent crashes`);
        } catch (error) {
            log(`Device ID hooks failed: ${error}`);
        }
    }
}