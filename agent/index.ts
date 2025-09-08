import { log } from "console";
import * as Scripts from "./scripts/modules";
import { Logger } from "./utils/logger";
import Java from "frida-java-bridge";

export const logLevel = Logger.LogLevel.INFO;
const logLevelNames = {
    [Logger.LogLevel.ERROR]: "ERROR",
    [Logger.LogLevel.INFO]: "INFO",
    [Logger.LogLevel.DEBUG]: "DEBUG",
    [Logger.LogLevel.VERBOSE]: "VERBOSE"
};

/**
 * https://www.piliapp.com/symbol/line/
 */

if (Java.available) {
    Java.performNow(() => {
        Logger.setLogLevel(logLevel);

        console.log(
            "\n"
            + "\n██████╗░░░░██████╗░░░░███████╗░░░██████╗░"
            + "\n██╔══██╗░░░██╔══██╗░░░██╔════╝░░░██╔══██╗"
            + "\n██║░░██║░░░██████╔╝░░░█████╗░░░░░██████╔╝"
            + "\n██║░░██║░░░██╔══██╗░░░██╔══╝░░░░░██╔═══╝░"
            + "\n██████╔╝██╗██║░░██║██╗███████╗██╗██║░░░░░"
            + "\n╚═════╝░╚═╝╚═╝░░╚═╝╚═╝╚══════╝╚═╝╚═╝░░░░░"
            + "\n\x1b[31mⲃⲩ ⲥⲩⲛⲩⲥⲏⲱꞅ\x1b[0m"
            + `\n\x1b[33mLog Level: ${logLevelNames[logLevel]}\x1b[0m\n`
        )

        console.log("\n\x1b[34m╓──────────────── STARTING UP HOOKS ──────────────────╖\x1b[0m");
        console.log("\x1b[34m╚═════════════════════════════════════════════════════╝\x1b[0m");

        // Execute comprehensive modular hook structure
        Scripts.Cloaking.performNow();      // Complete anti-detection bypass (root, debug, SSL, spoofing)
        Scripts.DevTools.performNow();      // Analysis tools (cipher, base64)
        Scripts.Monitoring.performNow();    // Monitoring tools (SharedPreferences)

        // Legacy experimental hooks
        Scripts.Scratchpad.performNow();

        console.log("\x1b[32m╓─────────────────────── LOGS ────────────────────────╖\x1b[0m");
        console.log("\x1b[32m╚═════════════════════════════════════════════════════╝\x1b[0m");
    })
}