/**
 * fabs/js/cojoin.js
 *
 * Handles both the Contact Us and Join Us forms. It performs honeypot and
 * malicious-content checks, manages dynamic form sections for the Join form,
 * and submits sanitized data to Cloudflare Worker endpoints with a simple
 * progress overlay.
 *
 * NOTE: Do not export raw symmetric keys from the client in production.
 *       See repository SECURITY.md / notes for hybrid encryption guidance.
 */

// Default Cloudflare Worker endpoint for Join form (overrideable via global var)
const JOIN_WORKER_URL =
  window.JOIN_WORKER_URL || 'https://ops-join-intake.pure-sail-sole.workers.dev';

async function ensureSession() {
  try {
    await fetch('/api/session', { method: 'POST' });
  } catch (_) {
    /* ignore session errors */
  }
}

function initCojoinForms() {
  ensureSession();
  const contactForm = document.getElementById('contactForm');
  const joinForm = document.getElementById('joinForm');

  if (contactForm && !contactForm.dataset.cojoinInitialized) {
    if (!contactForm.querySelector('#hp_text')) {
      window.antibot.injectFormHoneypot(contactForm);
    }
    contactForm.addEventListener('submit', handleContactSubmit);
    contactForm.dataset.cojoinInitialized = 'true';
  }

  if (joinForm && !joinForm.dataset.cojoinInitialized) {
    if (!joinForm.querySelector('#hp_text')) {
      window.antibot.injectFormHoneypot(joinForm);
    }
    joinForm.addEventListener('submit', handleJoinSubmit);
    joinForm.dataset.cojoinInitialized = 'true';
    initJoinForm();
  }

  function startEncryptionProgress() {
    const overlay = document.createElement('div');
    overlay.className = 'encrypt-overlay';
    overlay.innerHTML = `
      <div class="encrypt-box">
        <p>Securing your data...</p>
        <div class="encrypt-progress"><div class="encrypt-bar"></div></div>
      </div>`;
    document.body.appendChild(overlay);
    const bar = overlay.querySelector('.encrypt-bar');
    return {
      update(pct) {
        if (bar) bar.style.width = pct + '%';
      },
      finish() {
        if (overlay && overlay.remove) overlay.remove();
      }
    };
  }

  function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  async function sendJson(data, endpoint, progress) {
    try {
      if (progress) progress.update(40);
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      if (progress) progress.update(95);
      if (!response.ok) {
        console.error('Request failed:', response.status);
      }
    } catch (error) {
      console.error('Network error or endpoint unreachable:', error);
    }
  }

  async function handleContactSubmit(e) {
    e.preventDefault();
    const form = e.target;
    if (window.antibot.isHoneypotTriggered(form)) {
      console.warn('Honeypot filled. Blocking form submission.');
      form.reset();
      return;
    }
    const tokenRes = await fetch('/api/csrf-token');
    const { token } = await tokenRes.json();
    const csrfField = form.querySelector('#csrfToken');
    if (csrfField) csrfField.value = token;
    const sanitizedData = window.antibot.cleanFormData(form);
    if (!sanitizedData) {
      alert('Potential malicious content detected. Submission blocked.');
      form.reset();
      return;
    }
    sanitizedData.nonce = crypto.randomUUID
      ? crypto.randomUUID()
      : Date.now().toString(36);
    const progress = startEncryptionProgress();
    await sendJson(sanitizedData, '/api/contact', progress);
    progress.update(100);
    setTimeout(() => progress.finish(), 300);
    alert('Contact form submitted successfully!');
    form.reset();
    if (window.hideActiveFabModal) {
      window.hideActiveFabModal();
    }
  }

  async function handleJoinSubmit(e) {
    e.preventDefault();
    const form = e.target;
    if (window.antibot.isHoneypotTriggered(form)) {
      console.warn('Honeypot filled. Blocking form submission.');
      form.reset();
      return;
    }
    const formSections = document.querySelectorAll('.form-section[data-section]');
    for (const section of formSections) {
      const inputs = section.querySelectorAll('input[type=text]');
      if (inputs.length > 0 && !section.classList.contains('completed')) {
        alert(`Please accept your entries in "${section.querySelector('h2').textContent}" or remove them.`);
        return;
      }
    }
    const sanitizedData = window.antibot.cleanFormData(form);
    if (!sanitizedData) {
      alert('Potential malicious content detected. Submission blocked.');
      form.reset();
      return;
    }
    sanitizedData.nonce = crypto.randomUUID
      ? crypto.randomUUID()
      : Date.now().toString(36);
    const progress = startEncryptionProgress();
    await sendJson({ form: sanitizedData }, JOIN_WORKER_URL, progress);
    progress.update(100);
    setTimeout(() => progress.finish(), 300);
    alert('Join form submitted successfully!');
    form.reset();
    resetJoinFormState();
    if (window.hideActiveFabModal) {
      window.hideActiveFabModal();
    }
  }

  function initJoinForm() {
    const formSections = document.querySelectorAll('.form-section[data-section]');
    formSections.forEach(section => {
      const addBtn = section.querySelector('.circle-btn.add');
      const removeBtn = section.querySelector('.circle-btn.remove');
      const acceptBtn = section.querySelector('.accept-btn');
      const editBtn = section.querySelector('.edit-btn');
      const inputsContainer = section.querySelector('.inputs');

      if (addBtn) {
        addBtn.addEventListener('click', () => {
          let field;
          if (section.dataset.section === 'Experience') {
            const count = inputsContainer.querySelectorAll('textarea').length + 1;
            field = document.createElement('textarea');
            field.rows = 3;
            field.placeholder = `tell us about your Experience ${count}`;
          } else if (section.dataset.section === 'Continued Education') {
            field = document.createElement('textarea');
            field.rows = 3;
            field.placeholder = 'Online Courses, Seminars, Webinars with Completion Certification';
          } else {
            field = document.createElement('input');
            field.type = 'text';
            field.placeholder = `Enter ${section.querySelector('h2').textContent.toLowerCase()}`;
          }
          inputsContainer.appendChild(field);
          field.focus();
        });
      }

      if (removeBtn) {
        removeBtn.addEventListener('click', () => {
          if (!section.classList.contains('completed')) {
            if (inputsContainer.lastElementChild) {
              inputsContainer.removeChild(inputsContainer.lastElementChild);
            }
          }
        });
      }

      if (acceptBtn) {
        acceptBtn.addEventListener('click', () => {
          const inputs = inputsContainer.querySelectorAll('input[type=text], textarea');
          if (inputs.length === 0) {
            alert('Add at least one entry.');
            return;
          }
          for (const input of inputs) {
            if (!input.value.trim()) {
              alert('Please fill out all fields before accepting.');
              return;
            }
          }
          toggleSectionState(section, true);
        });
      }

      if (editBtn) {
        editBtn.addEventListener('click', () => {
          toggleSectionState(section, false);
        });
      }
    });
  }

  function resetJoinFormState() {
    const formSections = document.querySelectorAll('.form-section[data-section]');
    formSections.forEach(section => {
      toggleSectionState(section, false);
      const inputsContainer = section.querySelector('.inputs');
      inputsContainer.innerHTML = '';
    });
  }

  function toggleSectionState(section, accepted) {
    const inputs = section.querySelectorAll('input[type=text], textarea');
    const acceptBtn = section.querySelector('.accept-btn');
    const editBtn = section.querySelector('.edit-btn');
    const addBtn = section.querySelector('.circle-btn.add');
    const removeBtn = section.querySelector('.circle-btn.remove');

    inputs.forEach(input => (input.disabled = accepted));

    if (accepted) {
      if (acceptBtn) acceptBtn.style.display = 'none';
      if (editBtn) editBtn.style.display = 'inline-block';
      if (addBtn) addBtn.disabled = true;
      if (removeBtn) removeBtn.disabled = true;
      section.classList.add('completed');
    } else {
      if (acceptBtn) acceptBtn.style.display = 'inline-block';
      if (editBtn) editBtn.style.display = 'none';
      if (addBtn) addBtn.disabled = false;
      if (removeBtn) removeBtn.disabled = false;
      section.classList.remove('completed');
    }
  }
}

window.initCojoinForms = initCojoinForms;
document.addEventListener('DOMContentLoaded', initCojoinForms);

