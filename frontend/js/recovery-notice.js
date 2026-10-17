// Owner notice when the recovery key was recreated by the person who manages the server
// (clea recover or clea new-recovery-key). Shown on every page the owner can visit, top right.
// The server answers 401/403 to anyone who is not the owner: then nothing is shown.
// It stays until the owner closes it (here or in Mon profil), checks the key or replaces it:
// the server keeps that state, so it is the same on every page and every device.
(function () {
  'use strict';

  function show() {
    const box = document.createElement('div');
    box.className = 'notice-toast glass glow-border';

    // Small label with a key icon, like the dashboard cards (mockup__card-label)
    const label = document.createElement('p');
    label.className = 'notice-toast__label';
    const NS = 'http://www.w3.org/2000/svg';
    const icon = document.createElementNS(NS, 'svg');
    icon.setAttribute('width', '14'); icon.setAttribute('height', '14');
    icon.setAttribute('viewBox', '0 0 24 24'); icon.setAttribute('fill', 'none');
    icon.setAttribute('stroke', 'currentColor'); icon.setAttribute('stroke-width', '2');
    icon.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', 'M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z');
    const dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('cx', '16.5'); dot.setAttribute('cy', '7.5'); dot.setAttribute('r', '.5');
    icon.append(path, dot);
    label.append(icon, document.createTextNode('Clé de secours'));
    box.setAttribute('role', 'alert');

    const text = document.createElement('p');
    text.className = 'notice-toast__text';
    text.textContent = 'Ta clé de secours a été recréée par la personne qui gère ou maintient le serveur. '
      + 'Ton ancienne clé ne marche plus.';

    const link = document.createElement('a');
    link.className = 'notice-toast__link';
    link.href = '/profile#recovery-title';
    link.textContent = 'Voir dans Mon profil';

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'notice-toast__close';
    close.setAttribute('aria-label', 'Fermer la notification');
    close.textContent = '×';

    function hide() {
      box.remove();
      document.removeEventListener('keydown', onKey);
      // Also hides the box in Mon profil if this page is Mon profil
      document.getElementById('recovery-host-hint')?.classList.remove('visible');
      fetch('/api/recovery-key/notice/dismiss', { method: 'POST' }).catch(() => {});
    }
    function onKey(e) { if (e.key === 'Escape') hide(); }

    close.addEventListener('click', hide);
    document.addEventListener('keydown', onKey);

    box.append(label, close, text, link);
    document.body.append(box);
  }

  fetch('/api/recovery-key')
    .then((res) => (res.ok ? res.json() : null))
    .then((data) => {
      if (!data) return;
      if (data.notice === true) show();
    })
    .catch(() => { /* no notice if the server cannot be reached */ });
})();
