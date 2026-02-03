export enum LogType {
  Info,
  Config,
  Hook,
  Debug,
  Verbose,
  Error,
  None,
}

export enum LogLevel {
  ERROR = 0,
  INFO = 1,
  DEBUG = 2,
  VERBOSE = 3,
}

// All logger state lives on globalThis so it's accessible from any thread
// context. Java hook callbacks run on ART threads where frida-compile
// module closures may not resolve correctly.
const G = globalThis as any

if (G.__dre_logger === undefined) {
  G.__dre_logger = {
    level: LogLevel.INFO as number,
    prefixes: {
      [LogType.Info]:    "\x1b[36m[i]",
      [LogType.Config]:  "\x1b[34m[*]",
      [LogType.Hook]:    "\x1b[32m[+]",
      [LogType.Debug]:   "\x1b[33m[?]",
      [LogType.Verbose]: "\x1b[35m[v]",
      [LogType.Error]:   "\x1b[31m[!]",
    } as Record<number, string>,
    thresholds: {
      [LogType.Error]:   LogLevel.ERROR,
      [LogType.Info]:    LogLevel.INFO,
      [LogType.Config]:  LogLevel.INFO,
      [LogType.Hook]:    LogLevel.INFO,
      [LogType.Debug]:   LogLevel.DEBUG,
      [LogType.Verbose]: LogLevel.VERBOSE,
      [LogType.None]:    -1,
    } as Record<number, number>,
    reset: "\x1b[0m",
    showStackTraces: false,
    seen: new Set<string>(),
  }
}

export function setShowStackTraces(show: boolean): void {
  G.__dre_logger.showStackTraces = show
}

export function getShowStackTraces(): boolean {
  return G.__dre_logger.showStackTraces ?? false
}

export function setLogLevel(level: LogLevel): void {
  G.__dre_logger.level = level
}

export function getLogLevel(): LogLevel {
  return G.__dre_logger.level
}

export function logOnce(type: LogType, title: string, text: string, dedupKey?: string): boolean {
  const key = dedupKey ?? text
  if (G.__dre_logger.seen.has(key)) return false
  G.__dre_logger.seen.add(key)
  log(type, title, text)
  return true
}

export function formatStackLog(stack: string): string {
  if (!getShowStackTraces()) return ""
  return `\n    Stack: ${stack}`
}

export function log(type: LogType = LogType.None, title: string = "", text: string) {
  const logger = G.__dre_logger
  const threshold = logger.thresholds[type]
  if (threshold !== undefined && threshold >= 0 && logger.level < threshold) {
    return
  }

  const prefix = logger.prefixes[type]
  if (prefix) {
    console.log(prefix + title + logger.reset + " " + text)
  } else {
    console.log("[ ]" + title + " " + text)
  }
}
