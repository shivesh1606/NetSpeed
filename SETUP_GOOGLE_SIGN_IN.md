# Google Sign-In Setup Instructions

To complete the Google Sign-In integration, follow these steps:

## 1. Create a Firebase Project
1. Go to the [Firebase Console](https://console.firebase.google.com/)
2. Click "Add Project" and follow the setup process
3. Enter your project name and click "Continue"
4. Enable or disable Google Analytics (optional) and click "Continue"

## 2. Register Your Android App
1. In the Firebase Console, click the Android icon to add an Android app
2. Enter your package name: `com.example.netspeedv3`
3. Enter a nickname for your app (optional)
4. Download the `google-services.json` file

## 3. Add the Configuration File
1. Place the downloaded `google-services.json` file in your app's module directory: `app/`
2. Replace the placeholder file in this project with the actual one

## 4. Configure Google OAuth
1. In the Firebase Console, go to Authentication
2. Click "Sign-in method" tab
3. Enable "Google" as a sign-in provider
4. Save the configuration

## 5. Get Your Web Client ID
1. In the Firebase Console, go to Project Settings
2. Scroll down to "Your apps" section
3. Find your Android app and click on the configuration icon
4. Copy the "Web client ID" 
5. Replace `YOUR_WEB_CLIENT_ID_HERE` in `app/src/main/res/values/strings.xml` with the actual Web Client ID

## 6. SHA Certificate Fingerprints
1. In Firebase Console Project Settings, add your SHA-1 and SHA-256 fingerprints
2. To get your debug SHA fingerprint, run:
   ```bash
   keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
   ```
3. For release SHA fingerprint, use your release keystore file

## 7. Add Dependencies (Already Done)
The necessary dependencies have already been added to your project:
- `com.google.android.gms:play-services-auth`
- `com.google.firebase:firebase-auth`

## 8. Update the Strings Resource
In `app/src/main/res/values/strings.xml`, replace the placeholder:
```xml
<string name="default_web_client_id">YOUR_ACTUAL_WEB_CLIENT_ID_FROM_FIREBASE</string>
```

After completing these steps, Google Sign-In should work in your application.