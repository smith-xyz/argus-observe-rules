async function dynamic(expr, args, body, mod) {
  const result = eval(expr);
  const fn = new Function(args, body);
  const loaded = await import(mod);
  return { result, fn, loaded };
}
