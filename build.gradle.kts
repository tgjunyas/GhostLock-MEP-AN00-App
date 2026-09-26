// Java-only on purpose: no Kotlin plugin, no Compose, no AndroidX. Every extra
// plugin is another thing that can fail in CI, and this app needs three buttons.
plugins {
    id("com.android.application") version "8.7.3" apply false
}
