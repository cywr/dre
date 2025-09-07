// New modular hook structure
export * from "./hooks";

// Legacy system exports (deprecated - use hooks instead)
// export * from "./system/rooting";     // → Now: hooks/cloaking.ts (antiRoot)
// export * from "./system/debug";      // → Now: hooks/classes/android.os.Debug.ts
// export * from "./system/spoofing";   // → Keep for now (complex, needs separate migration)
// export * from "./system/sslPinning"; // → Now: hooks/cloaking.ts (sslPinningBypass)
// export * from "./system/cipher";     // → Now: hooks/tools/cipher.ts
// export * from "./system/base64";     // → Now: hooks/tools/base64.ts
// export * from "./system/sharedPreferencesWatcher"; // → Keep for now
// export * from "./scratchpad";        // → Keep for now