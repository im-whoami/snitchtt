package ai.snitchtt

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri

/**
 * Auto-initializes the native library before Application.onCreate().
 * Declared in the manifest with android:initOrder="2147483647" so it runs
 * at the highest possible priority — earlier than any other ContentProvider
 * and earlier than Application.onCreate(), closing the window between
 * process fork and library load.
 *
 * Consuming apps do NOT need to call anything; the library loads automatically.
 * Snitchtt.init() can still be called from Application.onCreate() to configure
 * options and start the monitor thread.
 */
internal class SnitchProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        SnitchNative  // triggers System.loadLibrary("snitchtt") + JNI_OnLoad
        return true
    }

    override fun query(uri: Uri, p: Array<String>?, s: String?, sA: Array<String>?, so: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, sA: Array<String>?): Int = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, sA: Array<String>?): Int = 0
}
