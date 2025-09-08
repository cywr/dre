import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.widget.ImageView class to control image operations and resource usage.
 */
export namespace AndroidWidgetImageView {
    const NAME = "[ImageView]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            cutResources();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Control image view methods to manage resource usage.
     */
    function cutResources(): void {
        try {
            const ImageView = Java.use("android.widget.ImageView");
            
            try {
                ImageView.setImageResource.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setImageResource blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setImageResource hook failed: ${error}`);
            }

            try {
                ImageView.setImageURI.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setImageURI blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setImageURI hook failed: ${error}`);
            }

            try {
                ImageView.setImageDrawable.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setImageDrawable blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setImageDrawable hook failed: ${error}`);
            }

            try {
                ImageView.setImageIcon.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setImageIcon blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setImageIcon hook failed: ${error}`);
            }

            try {
                ImageView.setImageTintList.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setImageTintList blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setImageTintList hook failed: ${error}`);
            }

            try {
                ImageView.setImageBitmap.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setImageBitmap blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setImageBitmap hook failed: ${error}`);
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `cutResources failed: ${error}`);
        }
    }
}