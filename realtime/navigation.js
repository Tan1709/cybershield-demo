// Client-side navigation helper (single-source-of-truth via server session).
// Usage (no HTML changes required):
//  - Realtime pages: <script src="/realtime/navigation.js"></script>
//  - Upload pages:   <script src="/upload/navigation.js"></script>
(function () {
  'use strict';

  const AUTH_STATUS_URL = '/auth/status';
  const SET_MODE_URL = '/set_upload_mode';

  // NOTE: upload landing uses the explicit HTML path requested by you
  const CANONICAL = {
    realtime: {
      dashboard: '/realtime/dashboard',
      'log analysis': '/realtime/log-analysis.html',
      'anomaly detection': '/realtime/anomaly.html',
      anomalydetection: '/realtime/anomaly.html',
      report: '/realtime/report.html'
    },
    // user requested explicit redirect to upload/udashboard
    upload: {
      dashboard: '/upload/udashboard'
    }
  };

  async function getAuthStatus() {
    try {
      const resp = await fetch(AUTH_STATUS_URL, { cache: 'no-store' });
      if (!resp.ok) return null;
      return await resp.json();
    } catch (err) {
      console.error('auth/status fetch failed', err);
      return null;
    }
  }

  async function setUploadModeBool(modeBool) {
    try {
      const resp = await fetch(SET_MODE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: modeBool })
      });
      if (!resp.ok) return null;
      return await resp.json();
    } catch (err) {
      console.error('set_upload_mode request failed', err);
      return null;
    }
  }

  function normalizeLabelText(el) {
    if (!el) return '';
    const t = (el.innerText || el.textContent || '').trim().toLowerCase();
    return t.replace(/\s+/g, ' ');
  }

  function destinationForLabel(label, serverMode) {
    if (serverMode) {
      if (CANONICAL.upload[label]) return CANONICAL.upload[label];
      if (label === 'dashboard') return CANONICAL.upload.dashboard;
    } else {
      if (CANONICAL.realtime[label]) return CANONICAL.realtime[label];
    }

    if (label.includes('upload')) return CANONICAL.upload.dashboard;
    const last = label.split(' ').pop();
    if (serverMode && CANONICAL.upload[last]) return CANONICAL.upload[last];
    if (!serverMode && CANONICAL.realtime[last]) return CANONICAL.realtime[last];
    return null;
  }

  function navigateTo(target, replace = false) {
    if (!target) return;
    const current = location.pathname.replace(/\/+$/, '');
    const tgt = target.replace(/\/+$/, '');
    if (current === tgt) return;
    if (replace) location.replace(target);
    else location.href = target;
  }

  // Wire menu items. Logout handled immediately in capture phase to avoid other handlers blocking it.
  function wireMenuItems() {
    const items = document.querySelectorAll('.menu-item');
    if (!items || items.length === 0) return;

    items.forEach((item) => {
      item.style.cursor = 'pointer';

      // Capture-phase: handle immediate actions (logout) synchronously
      item.addEventListener('click', (ev) => {
        const labelSpan = item.querySelector('span:not(.menu-icon)');
        const label = normalizeLabelText(labelSpan || item);
        if (label === 'logout' || label === 'log out' || label === 'log-out') {
          try { ev.preventDefault(); } catch (e) {}
          try { ev.stopImmediatePropagation(); } catch (e) {}
          try { ev.stopPropagation(); } catch (e) {}
          location.replace('/logout');
        }
      }, { capture: true, passive: true });

      // Bubble-phase: regular server-authoritative navigation
      item.addEventListener('click', async (ev) => {
        const labelSpan = item.querySelector('span:not(.menu-icon)');
        const label = normalizeLabelText(labelSpan || item);

        const status = await getAuthStatus();
        if (!status) {
          navigateTo(CANONICAL.upload.dashboard);
          return;
        }
        if (!status.authenticated) {
          navigateTo('/login');
          return;
        }
        const serverMode = Boolean(status.upload_mode);
        const dest = destinationForLabel(label, serverMode);
        if (!dest) {
          console.warn('No navigation mapping for menu label:', label);
          return;
        }
        navigateTo(dest);
      }, { passive: true });
    });
  }

  // Upload toggle: ensures default OFF state for log-analysis and report pages,
  // then toggles mode and redirects to upload dashboard when turned ON.
  function wireUploadToggle() {
    const toggle = document.getElementById('uploadToggle');
    if (!toggle) return;

    // Initialize the toggle visual state based on server
    async function initToggleState() {
      const status = await getAuthStatus();
      if (!status || !status.authenticated) return;
      
      const serverMode = Boolean(status.upload_mode);
      const currentPath = location.pathname.toLowerCase();
      
      // For log-analysis.html and report.html, ensure upload mode is OFF
      if (currentPath.includes('log-analysis') || currentPath.includes('report')) {
        // If server says upload_mode is ON but we're on these pages, force it OFF
        if (serverMode) {
          await setUploadModeBool(false);
          // Update toggle visual state to OFF
          toggle.classList.remove('active');
        } else {
          // Server already has it OFF, just sync the visual
          toggle.classList.remove('active');
        }
      } else {
        // For other pages, sync toggle visual state with server
        if (serverMode) {
          toggle.classList.add('active');
        } else {
          toggle.classList.remove('active');
        }
      }
    }

    // Call initialization on page load
    initToggleState();

    // Handle toggle click
    toggle.addEventListener('click', async () => {
      const status = await getAuthStatus();
      if (!status) {
        console.error('Cannot change upload mode: auth status unavailable');
        return;
      }
      if (!status.authenticated) {
        navigateTo('/login');
        return;
      }

      const serverMode = Boolean(status.upload_mode);
      const desired = !serverMode;

      const resp = await setUploadModeBool(desired);
      if (!resp || typeof resp.upload_mode === 'undefined') {
        console.error('Failed to set mode on server; aborting navigation');
        return;
      }
      const newMode = Boolean(resp.upload_mode);

      if (newMode === serverMode) return;

      // When toggled ON or OFF, always redirect to upload dashboard
      const target = CANONICAL.upload.dashboard;
      // use replace to avoid back-button returning to a wrong-mode page
      navigateTo(target, true);
    }, { passive: true });
  }

  // Enforce server-mode on page load. If user is on a disallowed path, redirect immediately.
  async function enforceModeOnLoad() {
    const status = await getAuthStatus();
    if (!status) return;
    if (!status.authenticated) return;

    const serverMode = Boolean(status.upload_mode);
    const path = location.pathname.replace(/\/+$/, '');

    if (serverMode) {
      if (!path.startsWith('/upload')) {
        location.replace(CANONICAL.upload.dashboard);
      }
      return;
    }

    if (!serverMode) {
      if (!path.startsWith('/realtime')) {
        location.replace(CANONICAL.upload.dashboard);
      }
    }
  }

  function init() {
    wireMenuItems();
    wireUploadToggle();
    enforceModeOnLoad();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();