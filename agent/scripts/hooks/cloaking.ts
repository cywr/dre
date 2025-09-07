import * as Classes from './classes';
import * as Native from './native';
import { Logger } from "../../utils/logger";

/**
 * Perform hooks on the system to bypass anti-rooting, anti-emulation validations and others.
 */
export namespace Cloaking {
    const NAME = "[Cloaking]";

    /**
     * Logs general information about the module.
     */
    export function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Debug`
            + `\n╓─┬\x1b[31m Anti-Detection Hooks \x1b[0m`
            + `\n║ ├── Anti-Rooting`
            + `\n║ ├── Anti-Debug`
            + `\n║ ├── SSL Pinning Bypass`
            + `\n║ └── System Spoofing`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    /**
     * Main hook method that orchestrates all anti-detection bypasses.
     */
    export function performNow(): void {
        info();
        try {
            antiRoot();
            antiDebug();
            sslPinningBypass();
            systemSpoofing();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`);
        }
    }

    /**
     * Perform hooks on the system to bypass anti-rooting validations.
     */
    function antiRoot(): void {
        Classes.ApplicationPackageManager.performNow();
        Classes.File.performNow();
        Classes.Runtime.performNow();
        Classes.ProcessBuilder.performNow();
        Classes.SystemProperties.performNow();
        Classes.String.performNow();
        Classes.BufferedReader.performNow();
        Native.libc.performNow();
    }

    /**
     * Perform hooks on the system to bypass anti-debug validations.
     */
    function antiDebug(): void {
        Classes.Debug.performNow();
    }

    /**
     * Perform hooks on the system to bypass SSL pinning validations.
     */
    function sslPinningBypass(): void {
        Classes.SSLContext.performNow();
        Classes.X509TrustManager.performNow();
        Classes.TrustManagerImpl.performNow();
    }

    /**
     * Perform system-level spoofing hooks.
     */
    function systemSpoofing(): void {
        // Add device spoofing hooks here when spoofing.ts is broken down
        // Classes.Build.hook(spoofedDevice);
        // Classes.TelephonyManager.hook(spoofedTelephony);
        // etc.
    }
}