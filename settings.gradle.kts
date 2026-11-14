// 本地与 GitHub Actions 共用同一份仓库配置。
// AGP 插件来自 dl.google.com；国内镜像作为兜底。
pluginManagement {
    repositories {
        maven { url = uri("https://dl.google.com/dl/android/maven2") }
        mavenCentral()
        gradlePluginPortal()
        maven { url = uri("https://maven.aliyun.com/repository/google") }
        maven { url = uri("https://maven.aliyun.com/repository/public") }
        maven { url = uri("https://maven.aliyun.com/repository/gradle-plugin") }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        maven { url = uri("https://dl.google.com/dl/android/maven2") }
        mavenCentral()
        maven { url = uri("https://maven.aliyun.com/repository/public") }
    }
}

rootProject.name = "HelloBBKActivationTool"
include(":app")
