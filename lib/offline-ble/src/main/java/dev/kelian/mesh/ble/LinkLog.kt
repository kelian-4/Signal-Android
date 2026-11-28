package dev.kelian.mesh.ble

import android.util.Log

fun interface LinkLog {
    fun log(level: Char, tag: String, msg: String)

    companion object {
        val ANDROID = LinkLog { level, tag, msg ->
            val t = "mesh-$tag"
            when (level) {
                'E' -> Log.e(t, msg)
                'W' -> Log.w(t, msg)
                'D' -> Log.d(t, msg)
                else -> Log.i(t, msg)
            }
        }
    }
}

fun LinkLog.i(tag: String, msg: String) = log('I', tag, msg)
fun LinkLog.w(tag: String, msg: String) = log('W', tag, msg)
fun LinkLog.e(tag: String, msg: String) = log('E', tag, msg)
fun LinkLog.d(tag: String, msg: String) = log('D', tag, msg)
