package tw.linemcp.app

import java.io.File

/** One bounded app-private diagnostic file; no line-sized allocations or logcat copy. */
internal class BoundedNodeLog(private val file: File, private val maxBytes: Int = 2_000_000) {
    init {
        require(maxBytes > 0)
        if (file.exists() && file.length() > maxBytes) file.writeBytes(byteArrayOf())
    }

    fun append(bytes: ByteArray, count: Int = bytes.size) {
        require(count in 0..bytes.size)
        val keep = minOf(count, maxBytes)
        if (file.length() + keep > maxBytes) file.writeBytes(byteArrayOf())
        java.io.FileOutputStream(file, true).use { it.write(bytes, count - keep, keep) }
    }

}
