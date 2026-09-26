plugins {
    id("com.android.application")
}

android {
    namespace = "dev.ghostlock.mepan00"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.ghostlock.mepan00"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Signed with the debug key so CI can emit an installable APK with no
            // secrets in the repo. This app is side-loaded, not published.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        // The privileged half lives behind AIDL (see IGhostLock.aidl).
        aidl = true
        buildConfig = true
    }

    // Keep the exploit as an extracted file in nativeLibraryDir; the app hands
    // its bytes to the shell side, which cannot read the app's data dir.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    lint {
        abortOnError = false
    }
}

dependencies {
    // Shell identity for the KASLR leak (tracefs is readtracefs-group only).
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
}
