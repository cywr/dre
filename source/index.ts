import Java from "frida-java-bridge"
import {
  AntiDebug,
  AntiEmulation,
  AntiRoot,
  Attribution,
  Base64,
  Cipher,
  DeviceSpoofing,
  Geolocation,
  NetworkMonitor,
  PIIWatcher,
  SharedPreferences,
  SSLPinning,
} from "./hooks"
import { Scratchpad } from "./scratchpad"
import { Country } from "./utils/enums"
import { LogLevel, setLogLevel } from "./utils/logger"
import { setActiveCountry } from "./utils/types"

if (Java.available) {
  setLogLevel(LogLevel.INFO)
  setActiveCountry(Country.SINGAPORE)

  Java.performNow(() => {
    // Anti-detection (no profile needed)
    AntiRoot.perform()
    AntiDebug.perform()
    AntiEmulation.perform()

    // Device & system spoofing (needs profile)
    DeviceSpoofing.perform()

    // PII access monitoring
    PIIWatcher.perform()

    // Geo & network spoofing + monitoring (needs profile)
    Geolocation.perform()
    NetworkMonitor.perform()

    // DCL.perform()
    // Reflection.perform()

    SharedPreferences.perform(
      [],
      [
        "com.google.android.gms",
        "com.facebook.ads",
        "com.appsflyer",
        "com.adjust",
        "com.crashlytics",
      ],
    )

    Base64.perform()
    Cipher.perform()
  })

  Java.perform(() => {
    Attribution.perform()
    SSLPinning.perform()

    Scratchpad.perform()
  })
}
