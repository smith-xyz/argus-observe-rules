package javareflectionstructuralmanipulation;

public class NegativeCases {
    public Object read(Object obj, String name) throws Exception {
        return obj.getClass().getField(name).get(obj);
    }
}
