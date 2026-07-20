function buildToken(header, payload) {
  return `${header}.${payload}.sig`;
}
