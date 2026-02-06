import { log as logMsg, LogType } from "./utils/logger"

/**
 * Scratchpad: Experimental workspace for testing hooks against a target app.
 * Runs inside Java.perform() from the entry point (index.ts).
 */
export namespace Scratchpad {
  const NAME = "[Scratchpad]"
  const log = (message: string) => logMsg(LogType.Hook, NAME, message)

  export function perform(): void {
    log("Scratchpad active")
  }
}
