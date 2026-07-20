function bufferOps(size, buffer) {
  const ab = new ArrayBuffer(size);
  const sab = new SharedArrayBuffer(size);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  return { ab, sab, view, bytes };
}
