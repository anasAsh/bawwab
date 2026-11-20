// Inert eval fixture (Shai-Hulud replica, v1 clean). Never executed.
function padStart(s, width, fill = " ") {
  s = String(s);
  while (s.length < width) s = fill + s;
  return s;
}

function padEnd(s, width, fill = " ") {
  s = String(s);
  while (s.length < width) s = s + fill;
  return s;
}

module.exports = { padStart, padEnd };
