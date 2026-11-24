import java.lang.reflect.InvocationTargetException
fun main(args: Array<String>) {
    var ok = 0; var ko = 0
    for (cn in args) {
        val c = Class.forName(cn)
        for (m in c.declaredMethods.sortedBy { it.name }) {
            if (m.getAnnotation(org.junit.Test::class.java) == null) continue
            val t = System.currentTimeMillis()
            try { m.invoke(c.getDeclaredConstructor().newInstance()); ok++; println("PASS ${c.simpleName}.${m.name} (${System.currentTimeMillis() - t}ms)") }
            catch (e: InvocationTargetException) { ko++; println("FAIL ${c.simpleName}.${m.name}: ${e.cause}") }
        }
    }
    println("RESULT passed=$ok failed=$ko")
    System.exit(if (ko == 0) 0 else 1)
}
