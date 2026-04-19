// Client-side navigation helper for UPLOAD pages.
// Include as <script src="/upload/navigation.js"></script> at end of each upload HTML file.
//
// Principles:
// - Single source of truth: ALWAYS query /auth/status for authoritative state.
// - Never trust UI classes for mode. Use /set_upload_mode to change server session.
// - Immediate logout in capture phase to avoid other handlers swallowing the event.
// - Avoid same-page reloads.

(function () {
  'use strict';

  const AUTH_STATUS_URL = '/auth/status';
  const SET_MODE_URL = '/set_upload_mode';

  // Canonical upload routes (match your filenames)
  const ROUTES = {
    'dashboard': '/upload/udashboard.html',
    'upload logs': '/upload/uupload.html',
    'uploadlogs': '/upload/uupload.html',
    'upload': '/upload/udashboard.html',
    'log analysis': '/upload/ulog-analysis.html',
    'loganalysis': '/upload/ulog-analysis.html',
    'anomaly detection': '/upload/uanomaly.html',
    'anomalydetection': '/upload/uanomaly.html',
    'report': '/upload/ureport.html',
    'logout': '/logout'
  };

  // Helper: fetch auth status from server
  async function getAuthStatus() {
    try {
      const res = await fetch(AUTH_STATUS_URL, { cache: 'no-store' });
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.error('auth/status failed', err);
      return null;
    }
  }

  // Helper: set upload mode on server (boolean)
  async function setUploadMode(modeBool) {
    try {
      const res = await fetch(SET_MODE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: modeBool })
      });
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.error('set_upload_mode failed', err);
      return null;
    }
  }

  // Normalize label text for matching
  function normalizeText(el) {
    if (!el) return '';
    const t = (el.innerText || el.textContent || '').trim().toLowerCase();
    return t.replace(/\s+/g, ' ');
  }

  // Avoid reloading when already on target
  function navigateTo(target, replace = false) {
    if (!target) return;
    const current = location.pathname.replace(/\/+$/, '');
    const tgt = target.replace(/\/+$/, '');
    if (current === tgt) return;
    if (replace) location.replace(target);
    else location.href = target;
  }

  // Decide destination given label and serverMode
  function destinationForLabel(label, serverMode) {
    // primary: exact upload mapping
    if (serverMode && ROUTES[label]) return ROUTES[label];

    // fallbacks:
    if (label.includes('upload')) return serverMode ? ROUTES['upload'] : '/realtime/dashboard';
    // last word fallback (handles emoji prefix)
    const last = label.split(' ').pop();
    if (serverMode && ROUTES[last]) return ROUTES[last];

    // default: if authenticated + upload_mode should be ON then dashboard, otherwise realtime
    return serverMode ? ROUTES['dashboard'] : '/realtime/dashboard';
  }

  // Wire sidebar items: capture-phase logout, bubble-phase navigation
  function wireMenuItems() {
    const items = document.querySelectorAll('.menu-item');
    if (!items || items.length === 0) return;

    items.forEach(item => {
      item.style.cursor = 'pointer';

      // Capture-phase immediate logout
      item.addEventListener('click', (ev) => {
        const labelSpan = item.querySelector('span:not(.menu-icon)');
        const label = normalizeText(labelSpan || item);
        if (label === 'logout' || label === 'log out' || label === 'log-out') {
          try { ev.preventDefault(); } catch (e) {}
          try { ev.stopImmediatePropagation(); } catch (e) {}
          try { ev.stopPropagation(); } catch (e) {}
          // Replace so back doesn't re-open protected pages
          location.replace('/logout');
        }
      }, { capture: true, passive: true });

      // Bubble-phase: server-authoritative navigation
      item.addEventListener('click', async () => {
        const labelSpan = item.querySelector('span:not(.menu-icon)');
        const label = normalizeText(labelSpan || item);

        const status = await getAuthStatus();
        if (!status) {
          // if server unreachable, conservative fallback to realtime landing
          navigateTo('/realtime/dashboard');
          return;
        }

        if (!status.authenticated) {
          // not authenticated -> server will redirect to login when navigating
          navigateTo('/login');
          return;
        }

        const serverMode = Boolean(status.upload_mode);

        // If serverMode is false, upload pages are blocked -> redirect to realtime dashboard
        if (!serverMode) {
          navigateTo('/realtime/dashboard', true);
          return;
        }

        // serverMode true -> choose upload destination
        const dest = destinationForLabel(label, serverMode);
        if (!dest) {
          console.warn('No mapping for', label);
          return;
        }
        navigateTo(dest);
      }, { passive: true });
    });
  }

  // Wire upload toggle: always consult server, request opposite, then redirect according to authoritative result.
  function wireUploadToggle() {
    const uploadToggle = document.getElementById('uploadToggle');
    if (!uploadToggle) return;

    uploadToggle.addEventListener('click', async () => {
      const status = await getAuthStatus();
      if (!status) {
        console.error('Cannot toggle: auth/status unavailable');
        return;
      }
      if (!status.authenticated) {
        navigateTo('/login');
        return;
      }

      const serverMode = Boolean(status.upload_mode);
      const desired = !serverMode;

      const resp = await setUploadMode(desired);
      if (!resp || typeof resp.upload_mode === 'undefined') {
        console.error('Failed to set mode on server');
        return;
      }

      const newMode = Boolean(resp.upload_mode);
      if (newMode === serverMode) {
        // nothing changed
        return;
      }

      // If upload turned OFF -> go to realtime dashboard
      if (!newMode) {
        navigateTo('/realtime/dashboard', true);
        return;
      }

      // If upload turned ON -> go to explicit upload udashboard.html
      navigateTo('/upload/udashboard.html', true);
    }, { passive: true });
  }

  // Sync toggle visual with server state on load (purely visual; server is authoritative)
  async function syncToggleUI() {
    const uploadToggle = document.getElementById('uploadToggle');
    if (!uploadToggle) return;
    try {
      const status = await getAuthStatus();
      if (!status) return;
      if (status.upload_mode) uploadToggle.classList.add('active');
      else uploadToggle.classList.remove('active');
    } catch (err) {
      // don't block if sync fails
      console.warn('Failed to sync upload toggle UI', err);
    }
  }

  // On load enforce server-mode: if server says upload_mode is false, redirect to realtime.
  async function enforceModeOnLoad() {
    const status = await getAuthStatus();
    if (!status) return;
    if (!status.authenticated) return;

    const serverMode = Boolean(status.upload_mode);
    const path = location.pathname.replace(/\/+$/, '');

    if (!serverMode) {
      // upload mode disabled -> upload pages not allowed
      if (!path.startsWith('/realtime')) {
        location.replace('/realtime/dashboard');
      }
    } else {
      // upload mode enabled -> ensure we are inside /upload
      if (!path.startsWith('/upload')) {
        location.replace('/upload/udashboard.html');
      }
    }
  }

  // Initialize
  function init() {
    wireMenuItems();
    wireUploadToggle();
    syncToggleUI();
    enforceModeOnLoad();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();