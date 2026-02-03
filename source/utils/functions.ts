import Java from "frida-java-bridge"

// Shared access log entry type
export interface AccessEntry {
  timestamp: number
  api: string
  value: string
  stack: string
  category?: string
}

// Capture Java stack trace (always captures, for access log storage)
export function getStackTrace(maxFrames: number = 10): string {
  try {
    const Exception = Java.use("java.lang.Exception")
    const exception = Exception.$new()
    const stackElements = exception.getStackTrace()
    const frames: string[] = []
    const limit = Math.min(stackElements.length, maxFrames)
    for (let i = 0; i < limit; i++) {
      frames.push(stackElements[i].toString())
    }
    return frames.join("\n    ")
  } catch (e) {
    return `[Could not get stack trace: ${e}]`
  }
}

export var bin2ascii = function (input: any) {
  try {
    var buffer = Java.array("byte", input)
    var result = ""

    for (var i = 0; i < buffer.length; ++i) {
      if (buffer[i] > 31 && buffer[i] < 127) result += String.fromCharCode(buffer[i])
      else result += " "
    }
    return result
  } catch (error) {
    return `(ERROR) - It wasn't possible to transform ${input} into String.`
  }
}

export var bin2hex = function (bytes: number[]) {
  try {
    return Array.from(bytes, function (byte: number) {
      return ("0" + (byte & 0xff).toString(16)).slice(-2)
    }).join(" ")
  } catch (error) {
    return `(ERROR) - It wasn't possible to transform ${bytes} into String.`
  }
}
