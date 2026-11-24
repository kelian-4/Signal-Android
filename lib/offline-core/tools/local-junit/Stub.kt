package org.junit

@Retention(AnnotationRetention.RUNTIME) @Target(AnnotationTarget.FUNCTION) annotation class Test

object Assert {
    fun fail(m: String): Nothing = throw AssertionError(m)
    fun assertTrue(c: Boolean) { if (!c) throw AssertionError("expected true") }
    fun assertTrue(m: String, c: Boolean) { if (!c) throw AssertionError(m) }
    fun assertFalse(c: Boolean) { if (c) throw AssertionError("expected false") }
    fun assertFalse(m: String, c: Boolean) { if (c) throw AssertionError(m) }
    fun assertNull(o: Any?) { if (o != null) throw AssertionError("expected null") }
    fun assertNotNull(o: Any?) { if (o == null) throw AssertionError("expected not null") }
    fun assertEquals(e: Any?, a: Any?) { if (e != a) throw AssertionError("expected <$e> but was <$a>") }
    fun assertEquals(e: Long, a: Long) { if (e != a) throw AssertionError("expected <$e> but was <$a>") }
    fun assertNotEquals(e: Any?, a: Any?) { if (e == a) throw AssertionError("expected different") }
}
