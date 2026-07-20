function mutate(obj, key, value) {
  Reflect.set(obj, key, value);
  Reflect.deleteProperty(obj, key);
  Object.defineProperty(obj, key, { value });
}
