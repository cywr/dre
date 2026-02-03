/**
 * Singleton profile manager for country-based device profiles
 */

import { CountryProfile } from "../interfaces/spoofing"
import { Country } from "../enums/country"
import { COUNTRY_PROFILES } from "./profiles"

let activeProfile: CountryProfile | null = null

export function setActiveCountry(country: Country): void {
  const profile = COUNTRY_PROFILES[country]
  if (!profile) {
    throw new Error(`No profile found for country: ${country}`)
  }
  activeProfile = profile
}

export function getActiveProfile(): CountryProfile {
  if (!activeProfile) {
    throw new Error("No active profile set. Call setActiveCountry() first.")
  }
  return activeProfile
}

export function getSecureSettings() {
  const profile = getActiveProfile()
  return {
    android_id: profile.device.ANDROID_ID,
    mock_location: "0",
    auto_time: 1,
    development_settings_enabled: 0,
    adb_enabled: 0,
    airplane_mode_on: 0,
  } as const
}

export function getGlobalSettings() {
  return {
    adb_enabled: 0,
    development_settings_enabled: 0,
    stay_on_while_plugged_in: 0,
    auto_time: 1,
    auto_time_zone: 1,
    mobile_data: 1,
    airplane_mode_on: 0,
  } as const
}
