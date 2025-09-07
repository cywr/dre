import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.app.ApplicationPackageManager class to bypass package detection.
 */
export namespace AndroidAppApplicationPackageManager {
    const NAME = "[PackageManager]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    const ROOTING_PACKAGES = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer",
        "com.saurik.substrate",
        "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree",
        "com.formyhm.hiderootPremium",
        "com.formyhm.hideroot",
        "me.phh.superuser",
        "eu.chainfire.supersu.pro",
        "com.kingouser.com"
    ];

    export function performNow(): void {
        try {
            const PackageManager = Java.use("android.app.ApplicationPackageManager");
            const NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
            
            PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName: string, flags: number) {
                if (ROOTING_PACKAGES.includes(packageName)) {
                    log(`PM.getPackageInfo: hiding ${packageName}`);
                    throw NameNotFoundException.$new(packageName);
                }

                return this.getPackageInfo.call(this, packageName, flags);
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}