package dev.kelian.mesh.core.protocol

/** Minimal JSON parser (objects, arrays, strings, numbers, booleans, null) so tests need no dependency. */
class MiniJson(private val s: String) {
    private var i = 0

    fun parse(): Any? {
        val v = value()
        ws()
        check(i == s.length) { "trailing data at $i" }
        return v
    }

    private fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }

    private fun value(): Any? {
        ws()
        return when (val c = s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> { i += 4; true }
            'f' -> { i += 5; false }
            'n' -> { i += 4; null }
            else -> if (c == '-' || c.isDigit()) num() else error("unexpected '$c' at $i")
        }
    }

    private fun obj(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        i++; ws()
        if (s[i] == '}') { i++; return m }
        while (true) {
            ws(); val k = str(); ws()
            check(s[i] == ':') { "expected ':' at $i" }; i++
            m[k] = value(); ws()
            if (s[i] == ',') { i++; continue }
            check(s[i] == '}') { "expected '}' at $i" }; i++
            return m
        }
    }

    private fun arr(): List<Any?> {
        val l = ArrayList<Any?>()
        i++; ws()
        if (s[i] == ']') { i++; return l }
        while (true) {
            l.add(value()); ws()
            if (s[i] == ',') { i++; continue }
            check(s[i] == ']') { "expected ']' at $i" }; i++
            return l
        }
    }

    private fun str(): String {
        check(s[i] == '"') { "expected string at $i" }; i++
        val sb = StringBuilder()
        while (s[i] != '"') {
            if (s[i] == '\\') {
                i++
                when (val e = s[i]) {
                    'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r')
                    'b' -> sb.append('\b'); 'f' -> sb.append('\u000C')
                    'u' -> { sb.append(s.substring(i + 1, i + 5).toInt(16).toChar()); i += 4 }
                    else -> sb.append(e)
                }
                i++
            } else { sb.append(s[i]); i++ }
        }
        i++
        return sb.toString()
    }

    private fun num(): Any {
        val st = i
        if (s[i] == '-') i++
        while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
        val t = s.substring(st, i)
        return if (t.any { it in ".eE" }) t.toDouble() else t.toLong()
    }
}
