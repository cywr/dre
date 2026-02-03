enum Color {
  Red = "\x1b[31m",
  Yellow = "\x1b[33m",
  Green = "\x1b[32m",
  Blue = "\x1b[34m",
  Cyan = "\x1b[36m",
  Magenta = "\x1b[35m",
}

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

let currentLogLevel: LogLevel = LogLevel.INFO

export function setLogLevel(level: LogLevel): void {
  currentLogLevel = level
}

export function getLogLevel(): LogLevel {
  return currentLogLevel
}

function shouldLog(type: LogType): boolean {
  switch (type) {
    case LogType.Error:
      return currentLogLevel >= LogLevel.ERROR
    case LogType.Info:
    case LogType.Config:
    case LogType.Hook:
      return currentLogLevel >= LogLevel.INFO
    case LogType.Debug:
      return currentLogLevel >= LogLevel.DEBUG
    case LogType.Verbose:
      return currentLogLevel >= LogLevel.VERBOSE
    case LogType.None:
    default:
      return true
  }
}

export function log(type: LogType = LogType.None, title: string = "", text: string) {
  if (!shouldLog(type)) {
    return
  }

  switch (type) {
    case LogType.Info:
      console.log(Color.Cyan + "[i]" + title + "\x1b[0m " + text)
      break
    case LogType.Config:
      console.log(Color.Blue + "[*]" + title + "\x1b[0m " + text)
      break
    case LogType.Hook:
      console.log(Color.Green + "[+]" + title + "\x1b[0m " + text)
      break
    case LogType.Debug:
      console.log(Color.Yellow + "[?]" + title + "\x1b[0m " + text)
      break
    case LogType.Verbose:
      console.log(Color.Magenta + "[v]" + title + "\x1b[0m " + text)
      break
    case LogType.Error:
      console.log(Color.Red + "[!]" + title + "\x1b[0m " + text)
      break
    default:
      console.log("[ ]" + title + " " + text)
      break
  }
}
