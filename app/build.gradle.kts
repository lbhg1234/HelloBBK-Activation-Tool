plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.hellobbk.activation"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.hellobbk.activation"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // 按要求【不签名】：不配置任何 signingConfig，产物为 app-release-unsigned.apk。
            // 未签名 APK 不能直接安装到普通设备，需自行签名或由宿主/调试流程加载。
        }
    }
}

// Material 3（Material Components for Android）：AppCompat + Material。
// 用于 M3 主题与组件；签名/验签核心仍为纯 JDK（java.security / java.util.Base64）。
dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
}
