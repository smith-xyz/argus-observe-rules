package javaynamicmethodinvocation;

public class NegativeCases {
    static class Sample {
        public String run() {
            return "ok";
        }
    }

    public String callDirect(Sample obj) {
        return obj.run();
    }
}
