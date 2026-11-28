### Fixed

- Move a server back to its connection service home when it stayed on an old home after a
  connection service restart. Before, the server showed as online, but no client could connect to
  it until it restarted. The fix is on the connection service, so it also works for servers on
  older versions.
