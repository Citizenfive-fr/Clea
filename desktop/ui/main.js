// Page de configuration : envoie l'adresse à l'app, qui la vérifie, l'enregistre et ouvre Cléa.
const form = document.getElementById('form');
const input = document.getElementById('server');
const error = document.getElementById('error');
const button = form.querySelector('button');

input.focus();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  error.textContent = '';
  if (!input.value.trim()) {
    error.textContent = "Indique l'adresse de ton Cléa.";
    input.focus();
    return;
  }
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Vérification…';
  form.setAttribute('aria-busy', 'true');
  try {
    await window.__TAURI__.core.invoke('set_server', { url: input.value });
  } catch (err) {
    error.textContent = String(err);
    input.focus();
  } finally {
    button.disabled = false;
    button.textContent = label;
    form.removeAttribute('aria-busy');
  }
});
