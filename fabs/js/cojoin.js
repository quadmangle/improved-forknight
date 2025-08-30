/**
 * fabs/js/cojoin.js
 *
 * This script contains the logic for both the Contact Us and Join Us forms.
 * It handles form submission, security checks (honeypot, malicious code),
 * and the dynamic form fields for the Join form.
 */

// Configuration and cryptography helpers for secure FAB submissions.
// Replace placeholder keys and URLs with production secrets.
const CFG = {
  sandwichURL: "https://sandwich-worker.pure-sail-sole.workers.dev/",
  ASSET_ID: "asset:fabs:v1", policyVer: 1,
  AES_F2S_BASE64: "<base64url-256bit>",          // FABs→Sandwich AES-GCM
  AESKW_URLS_BASE64: "<base64url-256bit>",       // wraps destination URL
  ASSET_FABS_PRIV_PEM: `-----BEGIN PRIVATE KEY-----\n...PKCS8...\n-----END PRIVATE KEY-----\n`,
  CONTACT_URL_CLEAR: "https://ops-join-intake.pure-sail-sole.workers.dev/contact",
  JOIN_URL_CLEAR:    "https://ops-join-intake.pure-sail-sole.workers.dev/join",
};
let encoder;
function getEncoder() {
  if (!encoder) {
    if (typeof TextEncoder !== 'undefined') {
      encoder = new TextEncoder();
    } else if (typeof require !== 'undefined') {
      encoder = new (require('util').TextEncoder)();
    } else {
      throw new Error('TextEncoder not available');
    }
  }
  return encoder;
}
const b64u = {
  e: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,""),
  d: s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)).buffer
};
const canon = o => JSON.stringify(o, Object.keys(o).sort());
async function importAESGCM(b64) { return crypto.subtle.importKey("raw", b64u.d(b64), { name: "AES-GCM" }, false, ["encrypt","decrypt"]); }
async function importAESKW(b64) { return crypto.subtle.importKey("raw", b64u.d(b64), { name: "AES-KW" }, false, ["wrapKey","unwrapKey"]); }
async function importPkcs8(pem) {
  const raw = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  return crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(raw), c => c.charCodeAt(0)), { name: "ECDSA", namedCurve: "P-384" }, false, ["sign"]);
}
function clean(s, max = 131072) {
  if (typeof s !== "string") s = "";
  if (s.length > max) throw Error("len");
  if (/[<>]/.test(s)) throw Error("html");
  const bad = /(script:|javascript:|on\w+=|<\s*script|\bselect\b.*\bfrom\b|\bdrop\b|\binsert\b|\bunion\b|\biframe\b)/i;
  if (bad.test(s)) throw Error("bad");
  return s.trim();
}
async function encField(key, name, val) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: getEncoder().encode(name) }, key, getEncoder().encode(val));
  return { iv: b64u.e(iv), ct: b64u.e(ct) };
}
async function wrapURL(kw, url) {
  const raw = getEncoder().encode(url);
  const tmp = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, []);
  return b64u.e(await crypto.subtle.wrapKey("raw", tmp, kw, "AES-KW"));
}
async function sign(priv, obj) {
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-384" }, priv, getEncoder().encode(canon(obj)));
  return b64u.e(sig);
}
const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
  const r = crypto.getRandomValues(new Uint8Array(1))[0] & 15;
  const v = c === 'x' ? r : (r & 3 | 8);
  return v.toString(16);
});
async function send(type, fields, destClear) {
  const aes = await importAESGCM(CFG.AES_F2S_BASE64);
  const kw = await importAESKW(CFG.AESKW_URLS_BASE64);
  const priv = await importPkcs8(CFG.ASSET_FABS_PRIV_PEM);
  const encFields = {};
  for (const [k, v] of Object.entries(fields)) {
    encFields[k] = await encField(aes, k, clean(v, k === "comments" || k === "about" ? 131072 : 8192));
  }
  const payload = {
    ver: 1,
    policyVer: CFG.policyVer,
    type,
    assetId: CFG.ASSET_ID,
    origin: location.origin,
    ts: Date.now(),
    jti: uuid(),
    destWrapped: await wrapURL(kw, destClear),
    fields: encFields
  };
  payload.sig = await sign(priv, payload);
  const r = await fetch(CFG.sandwichURL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!r.ok) throw Error("send");
  return r.json();
}

function initCojoinForms() {
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

  // Cryptographic helpers are defined globally above.

  /**
   * Contact Us form submission handler.
   * @param {Event} e The form submission event.
   */
  async function handleContactSubmit(e) {
    e.preventDefault();

    const form = e.target;
    // 1. Honeypot check
    if (window.antibot.isHoneypotTriggered(form)) {
      console.warn('Honeypot filled. Blocking form submission.');
      form.reset();
      return;
    }
    const sanitizedData = window.antibot.cleanFormData(form);
    if (!sanitizedData) {
      alert('Potential malicious content detected. Submission blocked.');
      form.reset();
      return;
    }
    try {
      await send('contact', sanitizedData, CFG.CONTACT_URL_CLEAR);
      alert('Contact form submitted successfully!');
    } catch (err) {
      console.error('Failed to send contact form:', err);
      alert('Unable to submit contact form at this time.');
    }
    form.reset();
    if (window.hideActiveFabModal) {
      window.hideActiveFabModal();
    }
  }

  /**
   * Join Us form submission handler.
   * @param {Event} e The form submission event.
   */
  async function handleJoinSubmit(e) {
    e.preventDefault();

    const form = e.target;
    // 1. Honeypot check
    if (window.antibot.isHoneypotTriggered(form)) {
      console.warn('Honeypot filled. Blocking form submission.');
      form.reset();
      return;
    }
    // Check that all dynamic sections are 'accepted' or empty
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
    try {
      await send('join', sanitizedData, CFG.JOIN_URL_CLEAR);
      alert('Join form submitted successfully!');
    } catch (err) {
      console.error('Failed to send join form:', err);
      alert('Unable to submit join form at this time.');
    }
    form.reset();
    resetJoinFormState();
    if (window.hideActiveFabModal) {
      window.hideActiveFabModal();
    }
  }

  /**
   * Initializes event listeners for the Join Us form's dynamic sections.
   */
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

  /**
   * Resets the Join Us form to its initial state after submission.
   */
  function resetJoinFormState() {
    const formSections = document.querySelectorAll('.form-section[data-section]');
    formSections.forEach(section => {
      toggleSectionState(section, false);
      const inputsContainer = section.querySelector('.inputs');
      inputsContainer.innerHTML = '';
    });
  }

  /**
   * Toggles the state of a dynamic form section (accepted/editable).
   * @param {HTMLElement} section The form section element.
   * @param {boolean} accepted True to lock the section, false to unlock.
   */
  function toggleSectionState(section, accepted) {
    const inputs = section.querySelectorAll('input[type=text], textarea');
    const acceptBtn = section.querySelector('.accept-btn');
    const editBtn = section.querySelector('.edit-btn');
    const addBtn = section.querySelector('.circle-btn.add');
    const removeBtn = section.querySelector('.circle-btn.remove');

    inputs.forEach(input => input.disabled = accepted);

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
