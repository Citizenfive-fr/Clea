// Redirect to setup if not configured
fetch('/api/setup/status')
  .then(r => r.json())
  .then(data => { if (!data.completed) window.location.href = '/setup'; })
  .catch(() => {});

// Adapt navbar auth button based on session
fetch('/api/auth/me')
  .then(r => r.ok ? r.json() : null)
  .then(user => {
    if (!user) return;
    const btn = document.getElementById('navbar-auth-btn');
    if (!btn) return;
    const name = user.username || user.email.split('@')[0];
    btn.textContent = name;
    btn.href = '/profile';
    btn.classList.remove('btn--ghost');
  })
  .catch(() => {});

// Navbar scroll
const navbar = document.getElementById('navbar');
function onScroll() {
  navbar.classList.toggle('is-scrolled', window.scrollY > 16);
}
window.addEventListener('scroll', onScroll, { passive: true });
onScroll();

// Mobile menu
const toggle     = document.getElementById('navbar-toggle');
const mobileMenu = document.getElementById('navbar-mobile');
const iconOpen   = document.getElementById('icon-open');
const iconClose  = document.getElementById('icon-close');

toggle.addEventListener('click', () => {
  const opening = mobileMenu.hidden;
  mobileMenu.hidden = !opening;
  iconOpen.hidden   = opening;
  iconClose.hidden  = !opening;
  toggle.setAttribute('aria-expanded', String(opening));
  toggle.setAttribute('aria-label', opening ? 'Fermer le menu' : 'Ouvrir le menu');
});

document.querySelectorAll('.navbar__mobile-link').forEach(link => {
  link.addEventListener('click', () => {
    mobileMenu.hidden = true;
    iconOpen.hidden   = false;
    iconClose.hidden  = true;
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Ouvrir le menu');
  });
});

// Typewriter
const WORDS = [
  'accessible',
  'universelle',
  'maîtrisée',
  'simplifiée',
  'claire',
];
const TYPING_SPEED       = 90;
const DELETING_SPEED     = 45;
const PAUSE_AFTER_TYPING = 1600;
const PAUSE_AFTER_DEL    = 400;

const visibleEl = document.getElementById('typewriter-text');
const srEl      = document.getElementById('typewriter-sr');

let wordIndex = 0;
let text      = '';
let phase     = 'typing';

function tick() {
  const current = WORDS[wordIndex];

  if (phase === 'typing') {
    if (text === current) {
      srEl.textContent = current;
      setTimeout(() => { phase = 'deleting'; tick(); }, PAUSE_AFTER_TYPING);
      return;
    }
    text = current.slice(0, text.length + 1);
    visibleEl.textContent = text;
    setTimeout(tick, TYPING_SPEED);
  } else {
    if (text === '') {
      setTimeout(() => {
        wordIndex = (wordIndex + 1) % WORDS.length;
        phase = 'typing';
        tick();
      }, PAUSE_AFTER_DEL);
      return;
    }
    text = current.slice(0, text.length - 1);
    visibleEl.textContent = text;
    setTimeout(tick, DELETING_SPEED);
  }
}

tick();
