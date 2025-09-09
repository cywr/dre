import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.content.ContentResolver class to spoof content queries, particularly GSF ID.
 */
export namespace ContentResolver {
    const NAME = "[ContentResolver]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    const spoofedDevice = {
        ANDROID_ID: "9774d56d682e549c",
        GSF_ID: "3f4c5e6d7a8b9c0d"
    };

    export function perform(): void {
        try {
            const ContentResolver = Java.use("android.content.ContentResolver");
            const MatrixCursor = Java.use("android.database.MatrixCursor");

            ContentResolver.query.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const result = this.query(...args);

                    try {
                        if (args[0].toString() === "content://com.google.android.gsf.gservices" && args[3] === "android_id") {
                            const gsfidHex = spoofedDevice.GSF_ID;
                            const gsfidDec = BigInt("0x" + gsfidHex);
                            const strArray = Java.array("java.lang.String", ["key", "value"]);
                            const objArray = Java.array("Ljava.lang.Object;", ["android_id", gsfidDec.toString()]);
                            const customCursor = MatrixCursor.$new(strArray);
                            customCursor.addRow(objArray);
                            log(`ContentResolver.query: spoofed GSF ID to ${gsfidHex} (${gsfidDec})`);
                            return customCursor;
                        }
                    } catch (error) {
                        log(`ContentResolver.query error: ${error}`);
                    }

                    return result;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}