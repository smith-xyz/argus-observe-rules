package javareflectionbasicusage;

public class TestCode {
    public void inspect(Object obj, String name) throws Exception {
        Class<?> runtime = obj.getClass();
        Class<?> loaded = Class.forName(name);
        java.lang.reflect.Method method = loaded.getDeclaredMethod("run");
        java.lang.reflect.Field field = loaded.getField("value");
        java.lang.reflect.Field declared = loaded.getDeclaredField("secret");
    }
}
