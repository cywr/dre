import { Logger } from "./utils/logger";
import * as Scripts from "./scripts/modules";

export const debug = true

if (Java.available) {
    Java.perform(() => {
        bypass([
            "deviceCloaking",
            "rooting",
            "debug",
            // "cipher",
            // "encoding",
            // "keystore",
            // "sharedPreferences",
            "scratchpad"
        ])
    });
} else {
    Logger.log(Logger.Type.Error, undefined, "\nJava is not available");
}

// # System Hooks
function bypass(validations:Array<string>) {
    Logger.log(Logger.Type.Info, undefined, "Hooks by Cynych Wr.");
    Logger.log(undefined, undefined, "######## STARTING UP HOOKS! ########\n");
    Logger.log(undefined, undefined, "# ###############  ############### #");
    validations.forEach(element => {
        switch(element){
            case "scratchpad":
                Scripts.Scratchpad.hook()
                break;
            case "deviceCloaking":
                Scripts.DeviceCloaking.hook()
                break;
            case "rooting":
                Scripts.Rooting.hook()
                break;
            case "debug":
                Scripts.Debug.hook()
                break;
            case "cipher":
                Scripts.Cipher.hook()
                break;
            case "encoding":
                Scripts.Encoding.hook()
                break;
            case "keystore":
                Scripts.KeyStore.hook()
                break;
            case "sharedPreferences":
                Scripts.SharedPreferences.hook("encrypted_preferences.xml")
            default:
                break;
        }
    });
    Logger.log(undefined, undefined, "# ###############  ############### #\n");
}