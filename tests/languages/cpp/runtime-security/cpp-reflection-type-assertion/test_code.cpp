struct Base {};
struct Derived : Base {};

void check_types(Base *b, void *p) {
    Derived *d = dynamic_cast<Derived *>(b);
    int *ip = static_cast<int *>(p);
    void *vp = reinterpret_cast<void *>(ip);
}
