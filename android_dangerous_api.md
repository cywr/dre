# PII Collection & Dangerous Permissions

## Table of Contents
- [Location Services](#location-services)
- [Camera & Microphone](#camera--microphone)
- [Contacts & Phone](#contacts--phone)
- [SMS & Call Logs](#sms--call-logs)
- [Storage Access](#storage-access)
- [Device Information](#device-information)
- [Network & Telephony](#network--telephony)
- [Alternative PII Access Methods](#alternative-pii-access-methods)
- [System Services & Dangerous Classes](#system-services--dangerous-classes)

---

## Location Services

### Required Permissions
- `android.permission.ACCESS_FINE_LOCATION` - GPS, precise location
- `android.permission.ACCESS_COARSE_LOCATION` - Network-based location
- `android.permission.ACCESS_BACKGROUND_LOCATION` - Location in background (API 29+)

### Key APIs & Classes
```java
// LocationManager - Primary location service
LocationManager locationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, minTime, minDistance, listener);
locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
locationManager.getBestProvider(criteria, enabledOnly);

// FusedLocationProviderClient - Google Play Services
FusedLocationProviderClient fusedLocationClient = LocationServices.getFusedLocationProviderClient(this);
fusedLocationClient.getLastLocation();
fusedLocationClient.requestLocationUpdates(locationRequest, locationCallback, Looper.myLooper());

// GnssStatusCallback - Detailed GPS info
GnssStatusCallback gnssStatusCallback = new GnssStatusCallback() {
    @Override
    public void onSatelliteStatusChanged(GnssStatus status) {
        // Access satellite info, signal strength
    }
};
```

### Detection Patterns
- Look for: `LocationManager`, `FusedLocationProviderClient`, `GnssStatus`
- Method calls: `getLastKnownLocation()`, `requestLocationUpdates()`, `getCellLocation()`
- Alternative access: `TelephonyManager.getCellLocation()`, `WifiManager.getScanResults()`

---

## Camera & Microphone

### Required Permissions
- `android.permission.CAMERA` - Camera access
- `android.permission.RECORD_AUDIO` - Microphone access
- `android.permission.WRITE_EXTERNAL_STORAGE` - Save media files (API ≤29)

### Key APIs & Classes
```java
// Camera APIs
Camera camera = Camera.open();
Camera2 camera2 = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
CameraX.bindToLifecycle(this, cameraSelector, preview, imageCapture);

// MediaRecorder - Audio/Video recording
MediaRecorder mediaRecorder = new MediaRecorder();
mediaRecorder.setAudioSource(MediaRecorder.AudioSource.MIC);
mediaRecorder.setVideoSource(MediaRecorder.VideoSource.CAMERA);
mediaRecorder.start();

// AudioRecord - Raw audio capture
AudioRecord audioRecord = new AudioRecord(MediaRecorder.AudioSource.MIC, 
    sampleRateInHz, channelConfig, audioFormat, bufferSizeInBytes);
audioRecord.startRecording();

// MediaStore - Camera without permission (scoped storage)
Intent takePictureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
```

### Detection Patterns
- Look for: `Camera`, `Camera2`, `CameraX`, `MediaRecorder`, `AudioRecord`
- Method calls: `takePicture()`, `startRecording()`, `read()` on AudioRecord
- File operations: Saving to `/sdcard/DCIM/`, `/Pictures/`, `/Movies/`

---

## Contacts & Phone

### Required Permissions
- `android.permission.READ_CONTACTS` - Read contact information
- `android.permission.WRITE_CONTACTS` - Modify contacts
- `android.permission.GET_ACCOUNTS` - Access account information
- `android.permission.READ_PHONE_STATE` - Device IDs, phone numbers
- `android.permission.READ_PHONE_NUMBERS` - Phone numbers (API 26+)

### Key APIs & Classes
```java
// ContactsContract - Contact database access
ContentResolver resolver = getContentResolver();
Cursor cursor = resolver.query(ContactsContract.Contacts.CONTENT_URI, null, null, null, null);
Cursor phoneCursor = resolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, ...);
Cursor emailCursor = resolver.query(ContactsContract.CommonDataKinds.Email.CONTENT_URI, ...);

// AccountManager - Account information
AccountManager accountManager = AccountManager.get(context);
Account[] accounts = accountManager.getAccounts();
Account[] googleAccounts = accountManager.getAccountsByType("com.google");

// TelephonyManager - Phone state and IDs
TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
String imei = telephonyManager.getDeviceId(); // Deprecated API 29
String imsi = telephonyManager.getSubscriberId();
String phoneNumber = telephonyManager.getLine1Number();
```

### Detection Patterns
- Look for: `ContactsContract`, `AccountManager`, `TelephonyManager`
- Content URIs: `content://com.android.contacts/contacts`, `content://com.android.contacts/data`
- Method calls: `getAccounts()`, `getDeviceId()`, `getSubscriberId()`

---

## SMS & Call Logs

### Required Permissions
- `android.permission.SEND_SMS` - Send SMS messages
- `android.permission.RECEIVE_SMS` - Receive SMS messages
- `android.permission.READ_SMS` - Read SMS messages
- `android.permission.READ_CALL_LOG` - Read call history
- `android.permission.WRITE_CALL_LOG` - Modify call history

### Key APIs & Classes
```java
// SmsManager - Send SMS
SmsManager smsManager = SmsManager.getDefault();
smsManager.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);

// Content Provider - Read SMS/MMS
ContentResolver resolver = getContentResolver();
Cursor cursor = resolver.query(Uri.parse("content://sms"), null, null, null, null);
Cursor mmsCursor = resolver.query(Uri.parse("content://mms"), null, null, null, null);

// CallLog - Call history
Cursor callCursor = resolver.query(CallLog.Calls.CONTENT_URI, null, null, null, null);

// Telephony Provider - Direct database access
Uri smsUri = Uri.parse("content://sms/inbox");
Uri outboxUri = Uri.parse("content://sms/outbox");
Uri sentUri = Uri.parse("content://sms/sent");
```

### Detection Patterns
- Look for: `SmsManager`, `CallLog`, `Telephony.Sms`
- Content URIs: `content://sms/*`, `content://mms/*`, `content://call_log/calls`
- Method calls: `sendTextMessage()`, `getAllMessagesFromIcc()`

---

## Storage Access

### Required Permissions
- `android.permission.READ_EXTERNAL_STORAGE` - Read external storage
- `android.permission.WRITE_EXTERNAL_STORAGE` - Write external storage
- `android.permission.MANAGE_EXTERNAL_STORAGE` - Full storage access (API 30+)

### Key APIs & Classes
```java
// Environment - Storage paths
File externalStorage = Environment.getExternalStorageDirectory();
File dcim = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM);
File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);

// MediaStore - Scoped storage (API 29+)
ContentResolver resolver = getContentResolver();
Uri collection = MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY);
ContentValues values = new ContentValues();

// File operations
File file = new File(Environment.getExternalStorageDirectory(), "sensitive_data.txt");
FileInputStream fis = new FileInputStream(file);
BufferedReader reader = new BufferedReader(new FileReader(file));
```

### Detection Patterns
- Look for: `Environment`, `MediaStore`, `File`, `FileInputStream`
- Paths: `/sdcard/`, `/storage/emulated/0/`, `getExternalFilesDir()`
- Common target files: Databases, images, documents, downloads

---

## Device Information

### Required Permissions
- `android.permission.READ_PHONE_STATE` - Device identifiers
- `android.permission.ACCESS_WIFI_STATE` - WiFi MAC address
- `android.permission.BLUETOOTH` - Bluetooth MAC address

### Key APIs & Classes
```java
// TelephonyManager - Device IDs
TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
String imei = telephonyManager.getDeviceId(); // Deprecated
String imsi = telephonyManager.getSubscriberId();
String serialNumber = Build.getSerial(); // Requires READ_PHONE_STATE

// Build class - Hardware info (No permission required)
String model = Build.MODEL;
String manufacturer = Build.MANUFACTURER;
String androidId = Settings.Secure.getString(resolver, Settings.Secure.ANDROID_ID);

// WifiManager - Network info
WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
WifiInfo wifiInfo = wifiManager.getConnectionInfo();
String macAddress = wifiInfo.getMacAddress(); // Randomized on API 23+

// BluetoothAdapter - Bluetooth info
BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
String btAddress = bluetoothAdapter.getAddress(); // Requires permission
```

### Detection Patterns
- Look for: `TelephonyManager`, `Build`, `Settings.Secure`, `WifiManager`, `BluetoothAdapter`
- Method calls: `getDeviceId()`, `getSerial()`, `getMacAddress()`
- Constants: `ANDROID_ID`, `SERIAL`, `MODEL`, `MANUFACTURER`

---

## Network & Telephony

### Required Permissions
- `android.permission.ACCESS_NETWORK_STATE` - Network connection state
- `android.permission.ACCESS_WIFI_STATE` - WiFi state and info
- `android.permission.READ_PHONE_STATE` - Cellular network info

### Key APIs & Classes
```java
// ConnectivityManager - Network status
ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
NetworkInfo activeNetwork = connectivityManager.getActiveNetworkInfo();
Network[] networks = connectivityManager.getAllNetworks();

// WifiManager - WiFi scanning and info
WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
List<ScanResult> scanResults = wifiManager.getScanResults();
List<WifiConfiguration> configs = wifiManager.getConfiguredNetworks();

// TelephonyManager - Cell tower info
TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
String networkOperator = telephonyManager.getNetworkOperator();
String networkOperatorName = telephonyManager.getNetworkOperatorName();
CellLocation cellLocation = telephonyManager.getCellLocation(); // Deprecated API 29
```

### Detection Patterns
- Look for: `ConnectivityManager`, `WifiManager`, `TelephonyManager`
- Method calls: `getScanResults()`, `getCellLocation()`, `getActiveNetworkInfo()`
- Network monitoring: Signal strength, cell tower IDs, WiFi SSIDs

---

## Alternative PII Access Methods

### No Permission Required Methods
```java
// Device fingerprinting without dangerous permissions
String androidId = Settings.Secure.getString(resolver, Settings.Secure.ANDROID_ID);
String buildSerial = Build.SERIAL; // "unknown" on API 26+ without permission
String model = Build.MODEL;
String brand = Build.BRAND;

// Display metrics
DisplayMetrics metrics = getResources().getDisplayMetrics();
int screenWidth = metrics.widthPixels;
int screenHeight = metrics.heightPixels;

// Sensor fingerprinting
SensorManager sensorManager = (SensorManager) getSystemService(Context.SENSOR_SERVICE);
List<Sensor> sensors = sensorManager.getSensorList(Sensor.TYPE_ALL);

// Installed apps (limited on API 30+)
PackageManager packageManager = getPackageManager();
List<PackageInfo> packages = packageManager.getInstalledPackages(0);
```

### Indirect PII Collection
```java
// ContentProvider queries (may bypass permissions)
ContentResolver resolver = getContentResolver();
// Some content providers may not properly check permissions

// System properties (reflection/native code)
Class<?> systemProperties = Class.forName("android.os.SystemProperties");
Method get = systemProperties.getMethod("get", String.class);
String prop = (String) get.invoke(null, "ro.serialno");

// Shared preferences of other apps
File sharedPrefsDir = new File("/data/data/[package]/shared_prefs/");
// Requires root or same UID

// Clipboard access
ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
ClipData clipData = clipboard.getPrimaryClip(); // Limited on API 29+
```

---

## System Services & Dangerous Classes

### Dangerous System Service Access
```java
// Accessibility Service - Can read screen content
AccessibilityService accessibilityService;
AccessibilityNodeInfo rootNode = getRootInActiveWindow();

// Device Administrator - Can wipe device, change settings
DevicePolicyManager devicePolicyManager = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);

// Notification Listener - Can read notifications
NotificationListenerService notificationListener;
StatusBarNotification[] notifications = getActiveNotifications();

// Usage Stats - App usage information
UsageStatsManager usageStatsManager = (UsageStatsManager) getSystemService(Context.USAGE_STATS_SERVICE);
```