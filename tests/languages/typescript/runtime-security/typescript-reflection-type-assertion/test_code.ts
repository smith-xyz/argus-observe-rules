function checkTypes(obj, type) {
  const isType = obj instanceof type;
  const tag = Object.prototype.toString.call(obj);
  return { isType, tag };
}
