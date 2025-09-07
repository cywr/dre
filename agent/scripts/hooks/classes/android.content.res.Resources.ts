import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.content.res.Resources class to spoof resources and display information.
 */
export namespace AndroidContentResResources {
    const NAME = "[Resources]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    const spoofedTelephony = {
        mcc: "310",
        mnc: "260"
    };

    export function performNow(): void {
        try {
            const Resources = Java.use("android.content.res.Resources");

            // Hook getConfiguration for MCC/MNC spoofing
            Resources.getConfiguration.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getConfiguration(...args);

                    const oldMcc = ret.mcc.value;
                    const newMcc = parseInt(spoofedTelephony.mcc);
                    ret.mcc.value = newMcc;
                    log(`Resources.getConfiguration: mcc ${oldMcc} -> ${newMcc}`);

                    const oldMnc = ret.mnc.value;
                    const newMnc = parseInt(spoofedTelephony.mnc);
                    ret.mnc.value = newMnc;
                    log(`Resources.getConfiguration: mnc ${oldMnc} -> ${newMnc}`);

                    return ret;
                };
            });

            // Hook getDisplayMetrics to spoof display metrics (Galaxy S10)
            Resources.getDisplayMetrics.implementation = function () {
                const ret = this.getDisplayMetrics();
                try {
                    ret.density.value = 3.0;
                    ret.densityDpi.value = 480;
                    ret.widthPixels.value = 1440;
                    ret.heightPixels.value = 3040;
                    ret.scaledDensity.value = 3.0;
                    ret.xdpi.value = 480.0;
                    ret.ydpi.value = 480.0;
                    log(`Resources.getDisplayMetrics: spoofed to Galaxy S10 metrics`);
                } catch (error) {
                    log(`Failed to spoof display metrics: ${error}`);
                }
                return ret;
            };

            // Hook getString to monitor potentially revealing strings
            Resources.getString.overload("int").implementation = function (id: number) {
                const ret = this.getString(id);
                if (ret && (ret.includes("emulator") || ret.includes("goldfish") || ret.includes("generic"))) {
                    log(`Resources.getString: potentially revealing string: ${ret}`);
                }
                return ret;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}