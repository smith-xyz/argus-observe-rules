package javareflectiontypeassertion;

public class NegativeCases {
    public String typeName(Object obj) {
        return obj.getClass().getName();
    }
}
