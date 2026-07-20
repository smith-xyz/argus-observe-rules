async function meshBypass(serviceIp, port) {
  const url = 'http://' + serviceIp + ':' + port;
  return fetch(url);
}
