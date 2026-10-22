/* Progressive enhancement only: every form and link works without this file.
   Loaded from 'self', so the strict Content-Security-Policy stays in place. */
(function () {
  'use strict';
  document.documentElement.classList.add('js');

  // Mobile navigation toggle
  var toggle = document.querySelector('.nav-toggle');
  var nav = document.querySelector('.nav-links');
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  // Confirm dialogs for destructive actions (form[data-confirm])
  document.addEventListener('submit', function (e) {
    var msg = e.target.getAttribute && e.target.getAttribute('data-confirm');
    if (msg && !window.confirm(msg)) { e.preventDefault(); }
  });

  // Prevent double submits (form[data-once]); re-enable if the page is restored from cache
  document.querySelectorAll('form[data-once]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (e.defaultPrevented) { return; }
      var btn = form.querySelector('button.primary');
      if (btn) {
        setTimeout(function () { btn.disabled = true; btn.textContent = 'Posting...'; }, 0);
      }
    });
  });
  window.addEventListener('pageshow', function (e) {
    if (!e.persisted) { return; }
    document.querySelectorAll('form[data-once] button.primary').forEach(function (b) { b.disabled = false; });
  });

  // Live character counters: <textarea data-counter="#id" data-min="5" data-max="150">
  document.querySelectorAll('[data-counter]').forEach(function (field) {
    var out = document.querySelector(field.getAttribute('data-counter'));
    if (!out) { return; }
    var min = parseInt(field.getAttribute('data-min') || '0', 10);
    var max = parseInt(field.getAttribute('data-max') || '0', 10);
    function update() {
      var n = field.value.trim().length;
      out.textContent = n + ' / ' + max;
      out.classList.toggle('low', n > 0 && n < min);
      out.classList.toggle('near', max > 0 && n > max * 0.95);
    }
    field.addEventListener('input', update);
    update();
  });

  // Show / hide password
  document.querySelectorAll('[data-toggle-password]').forEach(function (btn) {
    var input = document.querySelector(btn.getAttribute('data-toggle-password'));
    if (!input) { return; }
    btn.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
    });
  });

  // Live filter: <input data-filter="#users-table tbody tr">
  document.querySelectorAll('[data-filter]').forEach(function (box) {
    var rows = document.querySelectorAll(box.getAttribute('data-filter'));
    box.addEventListener('input', function () {
      var q = box.value.trim().toLowerCase();
      rows.forEach(function (row) {
        row.hidden = q !== '' && row.textContent.toLowerCase().indexOf(q) === -1;
      });
    });
  });

  // Close open <details class="menu"> popovers on outside click or Escape
  document.addEventListener('click', function (e) {
    document.querySelectorAll('details.menu[open]').forEach(function (d) {
      if (!d.contains(e.target)) { d.removeAttribute('open'); }
    });
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      document.querySelectorAll('details.menu[open]').forEach(function (d) { d.removeAttribute('open'); });
    }
  });
})();
