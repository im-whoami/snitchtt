plugins {
    alias(libs.plugins.android.library)    apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android)     apply false
}

subprojects {
    layout.buildDirectory.set(file("C:/tmp/snitchtt-build/${project.name}"))
}
