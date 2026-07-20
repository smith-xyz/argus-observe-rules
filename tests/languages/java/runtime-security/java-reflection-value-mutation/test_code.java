package javareflectionvaluemutation;

import java.lang.reflect.Field;

public class TestCode {
    public void mutateValues(Object obj, Field field, Object value) throws Exception {
        field.set(obj, value);
    }
}
