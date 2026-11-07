/* encrypt.one — applies the theme saved by the footer switcher before the
   page is drawn, so a dark page never flashes light. A classic blocking
   script on purpose; the switcher itself lives in app.js. */
try {
  const theme = localStorage.getItem('encrypt-one:theme');
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
} catch (e) { /* storage blocked: follow the system */ }
