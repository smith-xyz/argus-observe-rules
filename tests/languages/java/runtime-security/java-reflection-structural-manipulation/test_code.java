package javareflectionstructuralmanipulation;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class TestCode {
    public void mutate(Object obj, Field field, Method method, Object value) throws Exception {
        field.setAccessible(true);
        field.set(obj, value);
        method.setAccessible(true);
    }
}
