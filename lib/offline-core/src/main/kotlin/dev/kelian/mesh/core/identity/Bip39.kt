package dev.kelian.mesh.core.identity

import java.security.MessageDigest

object Bip39 {
    val wordlist: List<String> by lazy {
        val text = Bip39::class.java.getResourceAsStream("/bip39-english.txt")!!.bufferedReader().readText()
        text.split('\n').map { it.trim() }.filter { it.isNotEmpty() }.also { check(it.size == 2048) { "bad wordlist" } }
    }
    private val index by lazy { wordlist.withIndex().associate { it.value to it.index } }

    fun encode(entropy: ByteArray): List<String> {
        require(entropy.size == 32) { "24-word phrases encode exactly 32 bytes" }
        val bits = StringBuilder()
        for (b in entropy) bits.append(Integer.toBinaryString((b.toInt() and 0xFF) or 0x100).substring(1))
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)[0]
        bits.append(Integer.toBinaryString((checksum.toInt() and 0xFF) or 0x100).substring(1))
        return List(24) { wordlist[bits.substring(it * 11, it * 11 + 11).toInt(2)] }
    }

    fun decode(words: List<String>): ByteArray {
        require(words.size == 24) { "expected 24 words" }
        val bits = StringBuilder()
        for (w in words) {
            val i = index[w.trim().lowercase()] ?: throw IllegalArgumentException("unknown word")
            bits.append(Integer.toBinaryString(i or 0x800).substring(1))
        }
        val entropy = ByteArray(32) { bits.substring(it * 8, it * 8 + 8).toInt(2).toByte() }
        val expected = MessageDigest.getInstance("SHA-256").digest(entropy)[0].toInt() and 0xFF
        require(bits.substring(256, 264).toInt(2) == expected) { "bad checksum" }
        return entropy
    }

    fun parse(phrase: String): List<String> = phrase.trim().lowercase().split(Regex("\\s+"))
}
