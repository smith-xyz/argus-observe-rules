package javareflectiontypeassertion;

public class TestCode {
    public void checkTypes(Object obj, Class<?> type, Class<?> other) {
        boolean isString = obj instanceof String;
        boolean assignable = type.isAssignableFrom(other);
        boolean instance = type.isInstance(obj);
    }
}
