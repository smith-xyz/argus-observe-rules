function inspect(obj, key) {
  const value = Reflect.get(obj, key);
  const has = Reflect.has(obj, key);
  const keys = Reflect.ownKeys(obj);
  const t = typeof obj;
  const own = Object.keys(obj);
  return { value, has, keys, t, own };
}
