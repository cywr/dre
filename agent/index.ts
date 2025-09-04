import { Hook } from "./interfaces/hook";
import * as Scripts from "./scripts/modules";
import Java from "frida-java-bridge";

export const debug = false

/**
 * https://www.piliapp.com/symbol/line/
 */

if (Java.available) {
    Java.performNow(() =>{
        console.log(
            "\n"
            + "\n██████╗░░░░██████╗░░░░███████╗░░░██████╗░"
            + "\n██╔══██╗░░░██╔══██╗░░░██╔════╝░░░██╔══██╗"
            + "\n██║░░██║░░░██████╔╝░░░█████╗░░░░░██████╔╝"
            + "\n██║░░██║░░░██╔══██╗░░░██╔══╝░░░░░██╔═══╝░"
            + "\n██████╔╝██╗██║░░██║██╗███████╗██╗██║░░░░░"
            + "\n╚═════╝░╚═╝╚═╝░░╚═╝╚═╝╚══════╝╚═╝╚═╝░░░░░"
            + "\n\x1b[31mⲃⲩ ⲥⲩⲛⲩⲥⲏ ⲱꞅ.\x1b[0m\n"
        )
    })

    Java.perform(() => {
        console.log("\n\x1b[34m╓──────────────── STARTING UP HOOKS ──────────────────╖\x1b[0m");
        console.log("\x1b[34m╚═════════════════════════════════════════════════════╝\x1b[0m");
        
        bypass([
            new Scripts.DeviceCloaking(),
            new Scripts.Rooting(),
            new Scripts.Debug(),
            new Scripts.Spoofing(),
            new Scripts.SSLPinning(),

            // new Scripts.Cipher(),
            // new Scripts.Base64(),
            // new Scripts.SharedPreferencesWatcher(["decrypted_preferences.xml"]),
            
            new Scripts.Scratchpad(),
        ])

        console.log("\x1b[32m╓─────────────────────── LOGS ────────────────────────╖\x1b[0m");
        console.log("\x1b[32m╚═════════════════════════════════════════════════════╝\x1b[0m");
    });
}

function bypass(hooks:Array<Hook>) {
    hooks.forEach(hook => hook.execute());   
}