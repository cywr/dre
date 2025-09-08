import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.graphics.BitmapFactory class to control bitmap decoding operations.
 */
export namespace AndroidGraphicsBitmapFactory {
    const NAME = "[BitmapFactory]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            cutResources();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Control bitmap decoding methods to manage resource usage.
     */
    function cutResources(): void {
        try {
            const BitmapFactory = Java.use("android.graphics.BitmapFactory");
            
            try {
                BitmapFactory.decodeFile.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`decodeFile blocked`);
                        return null;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `decodeFile hook failed: ${error}`);
            }

            try {
                BitmapFactory.decodeResource.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`decodeResource blocked`);
                        return null;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `decodeResource hook failed: ${error}`);
            }

            try {
                BitmapFactory.decodeByteArray.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`decodeByteArray blocked`);
                        return null;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `decodeByteArray hook failed: ${error}`);
            }

            try {
                BitmapFactory.decodeStream.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`decodeStream blocked`);
                        return null;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `decodeStream hook failed: ${error}`);
            }

            try {
                BitmapFactory.decodeFileDescriptor.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`decodeFileDescriptor blocked`);
                        return null;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `decodeFileDescriptor hook failed: ${error}`);
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `cutResources failed: ${error}`);
        }
    }
}