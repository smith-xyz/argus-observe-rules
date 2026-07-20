function mutateValues(target, source, key, value) {
  Reflect.set(target, key, value);
  Object.assign(target, source);
}
