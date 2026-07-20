package javaynamicmethodinvocation;

import java.lang.reflect.Method;

public class TestCode {
    public Object callDynamic(Object obj, Class<?> clazz, String name, Object[] args)
        throws Exception {
        Object direct = clazz.getMethod(name).invoke(obj, args);
        Method method = clazz.getMethod(name);
        return method.invoke(obj, args);
    }
}
