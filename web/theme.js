try {
  const selected = localStorage.getItem('tg-relay-theme');
  document.documentElement.dataset.theme = selected === 'light' ? 'light' : 'dark';
} catch {}
