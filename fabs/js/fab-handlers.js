/**
 * fabs/js/fab-handlers.js
 *
 * Secure handlers for Contact/Join FAB forms. Validates, sanitizes and
 * encrypts form submissions before posting them to the worker endpoint.
 */

const WORKER_URL = 'https://sandwich-worker.pure-sail-sole.workers.dev/';

function sanitize(value) {
  if (!value) return value;
  if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
    return window.DOMPurify.sanitize(value);
  }
  if (window.appUtils && typeof window.appUtils.sanitizeInput === 'function') {
    return window.appUtils.sanitizeInput(value);
  }
  return value;
}

async function validateField(field, value, maxLength, regex, required = true) {
  if (required && !value) throw new Error(`${field} is required`);
  if (value && value.length > maxLength) throw new Error(`${field} exceeds ${maxLength} characters`);
  if (value && !regex.test(value)) throw new Error(`Invalid ${field} format`);
  return value ? sanitize(value) : value;
}

async function handleSubmit(event, workerUrl) {
  event.preventDefault();
  const form = event.target;
  const formData = new FormData(form);
  if (formData.get('hp_text')) {
    console.warn('Honeypot triggered');
    form.reset();
    return;
  }

  const formType = form.id === 'contactForm' ? 'contact' : 'join';
  const assetID = formType === 'contact'
    ? 'FABs_assetID_llamanos'
    : 'FABs_assetID_unete';

  const validatedData = { skills: [], education: [], certification: [], hobbies: [], continuedEducation: [], experience: [] };

  try {
    validatedData.name = await validateField('Name', formData.get('name'), 50, /^[\p{L}\s]{1,50}$/u);
    validatedData.email = await validateField('Email', formData.get('email'), 100, /^[^\s@]+@[^\s@]+\.[^\s@]+$/);
    validatedData.phone = await validateField('Phone', formData.get('phone'), 20, /^\+?[\d\s-]{7,20}$/, false);
    validatedData.interest = await validateField('Interest', formData.get('interest'), 50, /^(Business Operations|Contact Center|IT Support|Professionals)$/);

    if (form.id === 'contactForm') {
      validatedData.preferredDate = await validateField('Date', formData.get('preferredDate'), 10, /^\d{4}-\d{2}-\d{2}$/, false);
      validatedData.preferredTime = await validateField('Time', formData.get('preferredTime'), 5, /^\d{2}:\d{2}$/, false);
      validatedData.comments = await validateField('Comments', formData.get('comments'), 3000, /^[\p{L}0-9\s,.!?-]{0,3000}$/u, false);
    }

    if (form.id === 'joinForm') {
      for (const skill of formData.getAll('skills[]')) {
        validatedData.skills.push(await validateField('Skill', skill, 500, /^[\p{L}0-9\s,.]{1,500}$/u));
      }
      for (const edu of formData.getAll('education[]')) {
        validatedData.education.push(await validateField('Education', edu, 500, /^[\p{L}0-9\s,.]{1,500}$/u));
      }
      for (const cert of formData.getAll('certification[]')) {
        validatedData.certification.push(await validateField('Certification', cert, 500, /^[\p{L}0-9\s,.]{1,500}$/u));
      }
      for (const hobby of formData.getAll('hobbies[]')) {
        validatedData.hobbies.push(await validateField('Hobby', hobby, 500, /^[\p{L}0-9\s,.]{1,500}$/u));
      }
      for (const ce of formData.getAll('continuedEducation[]')) {
        validatedData.continuedEducation.push(await validateField('Continued Education', ce, 3000, /^[\p{L}0-9\s,.!?-]{0,3000}$/u));
      }
      for (const exp of formData.getAll('experience[]')) {
        validatedData.experience.push(await validateField('Experience', exp, 3000, /^[\p{L}0-9\s,.!?-]{0,3000}$/u));
      }
      validatedData.about = await validateField('About', formData.get('about'), 3000, /^[\p{L}0-9\s,.!?-]{0,3000}$/u, false);
    }

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = {};
    for (const [field, value] of Object.entries(validatedData)) {
      if (Array.isArray(value)) {
        encryptedData[field] = [];
        for (const v of value) {
          const encoded = new TextEncoder().encode(v);
          const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
          encryptedData[field].push(Array.from(new Uint8Array(cipher)));
        }
      } else if (value) {
        const encoded = new TextEncoder().encode(value);
        const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
        encryptedData[field] = Array.from(new Uint8Array(cipher));
      }
    }

    const ecdsaKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
    const exportedPublicKey = await crypto.subtle.exportKey('spki', ecdsaKey.publicKey);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      ecdsaKey.privateKey,
      new TextEncoder().encode(JSON.stringify(encryptedData))
    );

    const exportedKey = await crypto.subtle.exportKey('raw', key);

    const response = await fetch(workerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        formType,
        encryptedData,
        iv: Array.from(iv),
        signature: Array.from(new Uint8Array(signature)),
        publicKey: Array.from(new Uint8Array(exportedPublicKey)),
        aesKey: Array.from(new Uint8Array(exportedKey)),
        assetID
      })
    });

    if (!response.ok) throw new Error('Failed to send data to worker');

    alert('Form submitted successfully!');
    form.reset();
    if (window.hideActiveFabModal) {
      window.hideActiveFabModal();
    }
  } catch (error) {
    console.error(error);
    alert(`Error: ${error.message}`);
  }
}

function initFabHandlers() {
  const contact = document.getElementById('contactForm');
  if (contact && !contact.dataset.fabInit) {
    contact.addEventListener('submit', (e) => handleSubmit(e, WORKER_URL));
    contact.dataset.fabInit = 'true';
  }

  const join = document.getElementById('joinForm');
  if (join && !join.dataset.fabInit) {
    join.addEventListener('submit', (e) => handleSubmit(e, WORKER_URL));
    join.dataset.fabInit = 'true';
  }
}

window.initFabHandlers = initFabHandlers;
initFabHandlers();

export { initFabHandlers };
