// Home page typewriter. Setup and session redirects are done server side (routes/app.rs).
// Screen readers get the static word from the .sr-only span: the animated text is aria-hidden.
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

let wordIndex = 0;
let text      = '';
let phase     = 'typing';

function tick() {
  const current = WORDS[wordIndex];

  if (phase === 'typing') {
    if (text === current) {
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

if (visibleEl) {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    visibleEl.textContent = WORDS[0];
  } else {
    tick();
  }
}
