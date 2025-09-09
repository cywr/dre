import * as Hooks from "./hooks";
import { Scratchpad } from "./scratchpad";
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
    Java.perform(() => {
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

        Hooks.Cloaking.perform();
        Hooks.DevTools.perform();
        Hooks.Monitoring.perform();

        Scratchpad.perform();

        console.log("\x1b[32m╓─────────────────────── LOGS ────────────────────────╖\x1b[0m");
        console.log("\x1b[32m╚═════════════════════════════════════════════════════╝\x1b[0m");
    })
}