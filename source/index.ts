import Java from "frida-java-bridge"
import {
  AntiDebug,
  AntiEmulation,
  AntiFrida,
  AntiRoot,
  AntiTamper,
  Attribution,
  DCL,
  DeviceSpoofing,
  Geolocation,
  NetworkMonitor,
  PIIWatcher,
  Reflection,
  SharedPreferences,
  SSLPinning,
} from "./hooks"
import { NativeMonitor } from "./hooks/native"
import { Scratchpad } from "./scratchpad"
import { Country } from "./utils/enums"
import { LogLevel, setLogLevel, setShowStackTraces } from "./utils/logger"
import { setActiveCountry } from "./utils/types"

setLogLevel(LogLevel.INFO)
setShowStackTraces(false)
setActiveCountry(Country.BRAZIL)

if (Java.available) {
  // Java hooks FIRST — must run before native hooks to avoid
  // Interceptor conflicts with frida-java-bridge initialization.
  Java.performNow(() => {
    // Anti-detection
    AntiFrida.perform()
    AntiTamper.perform()
    AntiRoot.perform()
    AntiDebug.perform()
    AntiEmulation.perform()

    // Device & system spoofing
    DeviceSpoofing.perform()

    // PII access monitoring
    PIIWatcher.perform()

    // Geo & network spoofing + monitoring
    Geolocation.perform()
    NetworkMonitor.perform()

    SharedPreferences.perform()

    DCL.perform()
    Reflection.perform()

    // Base64.perform()
    // Cipher.perform()

    Attribution.perform()
  })

  Java.perform(() => {
    SSLPinning.perform()

    Scratchpad.perform()
  })

  // Native hooks AFTER Java bridge init — avoids Interceptor conflicts
  // with frida-java-bridge's internal hooks on libc functions.
  AntiFrida.performNative()
  AntiTamper.performNative()

  // Unified native monitoring
  // Unified native monitoring — uncomment and set target library:
  // NativeMonitor.perform("libtarget.so")
  // Use { skipSyscalls: true } if target native code crashes with libc hooks:
  // NativeMonitor.perform("libtarget.so", { skipSyscalls: true })
}
