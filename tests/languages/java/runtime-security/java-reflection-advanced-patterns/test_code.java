package javareflectionadvancedpatterns;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class TestCode {
    public Object advancedReflection(ClassLoader loader, String name, Object obj, Object[] args)
        throws Exception {
        Class<?> loaded = loader.loadClass(name);
        Class<?> initialized = Class.forName(name, true, loader);
        Object proxy = Proxy.newProxyInstance(
            loader,
            new Class<?>[] { Runnable.class },
            (p, method, a) -> null
        );
        Method method = loaded.getMethod("run");
        return method.invoke(obj, args);
    }
}
