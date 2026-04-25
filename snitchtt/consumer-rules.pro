-keep class ai.snitchtt.** { *; }
-keepclassmembers class ai.snitchtt.SnitchNative {
    public static native *;
    public static void onAlert(int);
}
