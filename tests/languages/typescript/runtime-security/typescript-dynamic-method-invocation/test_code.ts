function callDynamic(obj, method, arg) {
  const direct = obj[method](arg);
  const fn = obj[method];
  const indirect = fn(arg);
  return { direct, indirect };
}
