import { Hook } from "./interfaces/hook";
import * as Scripts from "./scripts/modules";

export const debug = true

/**
 * https://www.piliapp.com/symbol/line/
 */

if (Java.available) {
    Java.perform(() => {
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
        
        console.log("\x1b[34m╓──────────────── STARTING UP HOOKS ──────────────────╖\x1b[0m");
        console.log("\x1b[34m╚═════════════════════════════════════════════════════╝\x1b[0m");
        
        bypass([
            new Scripts.Rooting(),
            new Scripts.Debug(),
        ])

        console.log("\x1b[32m╓─────────────────────── LOGS ────────────────────────╖\x1b[0m");
        console.log("\x1b[32m╚═════════════════════════════════════════════════════╝\x1b[0m");
    });
}

function bypass(hooks:Array<Hook>) {
    hooks.forEach(hook => hook.execute());   
}