// Update auth button if logged in
fetch('/api/auth/me')
  .then(r => r.ok ? r.json() : null)
  .then(user => {
    if (!user) return;
    const btn = document.getElementById('navbar-auth-btn');
    if (!btn) return;
    btn.textContent = user.email.split('@')[0];
    btn.href = '/app';
  })
  .catch(() => {});

// Navbar scroll effect
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
