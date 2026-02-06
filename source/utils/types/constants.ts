/**
 * Constants for device bypass operations
 */

export const ROOT_DETECTION_COMMANDS = ["getprop", "mount", "build.prop", "id"] as const

export const SHARED_PREFERENCES_IGNORE_LIST = [
  "com.google.android.gms",
  "com.facebook.ads",
  "com.appsflyer",
  "appsflyer",
  "com.crashlytics",
  "adjust",
  "WebViewChromiumPrefs",
  "WebViewProfilePrefs",
  "AwOriginVisitLoggerPrefs",
] as const

export const DCL_IGNORE_LIST = [
  "java.",
  "android.",
  "androidx.",
  "dalvik.",
  "com.android.",
  "com.google.",
  "kotlin.",
  "kotlinx.",
  "org.chromium.",
  "com.facebook.",
  "com.appsflyer.",
  "com.adjust.",
] as const

export const REFLECTION_IGNORE_LIST = [
  "java.",
  "javax.",
  "android.",
  "androidx.",
  "dalvik.",
  "com.android.",
  "libcore.",
  "sun.",
  "kotlin.",
  "kotlinx.",
  "org.chromium.",
  "com.google.",
  "com.facebook.",
  "com.adjust.",
  "com.appsflyer.",
] as const

export const JNI_IGNORE_LIST = [
  "java/",
  "javax/",
  "android/",
  "androidx/",
  "dalvik/",
  "com/android/",
  "com/google/",
  "sun/",
  "libcore/",
  "kotlin/",
  "org/chromium/",
  "com/appsflyer/",
  "com/facebook/",
  "com/adjust/",
] as const

export const SYSCALL_FILE_IGNORE_LIST = [
  "/dev/ashmem",
  "/dev/binder",
  "/dev/hwbinder",
  "/dev/vndbinder",
  "/dev/null",
  "/dev/urandom",
  "/dev/zero",
  "/proc/self/maps",
  "/proc/self/status",
  "/proc/self/cmdline",
  "/sys/",
] as const

export const LINKER_IGNORE_LIST = [
  "libc.so",
  "libm.so",
  "libdl.so",
  "liblog.so",
  "libz.so",
  "libstdc++.so",
  "libandroid_runtime.so",
  "libhwui.so",
  "libEGL.so",
  "libGLES",
  "libvulkan.so",
  "libadreno",
  "vulkan.",
  "gralloc.",
  "libandroid.so",
  "libdexfile",
  "android.hardware.graphics",
] as const

export const DLSYM_IGNORE_LIST = [
  "egl",
  "gl",
  "vk",
  "AChoreographer",
  "HIDL_FETCH_",
  "HMI",
] as const
