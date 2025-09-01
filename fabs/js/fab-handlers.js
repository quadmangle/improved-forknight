/**
 * fabs/js/fab-handlers.js
 *
 * Handlers for Contact/Join FAB forms. Validates and sanitizes form submissions
 * without sending data to remote endpoints.
*/

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

async function handleSubmit(event) {
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

    console.log(`${formType} data:`, validatedData);
    alert('Form submission disabled.');
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
    contact.addEventListener('submit', handleSubmit);
    contact.dataset.fabInit = 'true';
  }

  const join = document.getElementById('joinForm');
  if (join && !join.dataset.fabInit) {
    join.addEventListener('submit', handleSubmit);
    join.dataset.fabInit = 'true';
  }
}

window.initFabHandlers = initFabHandlers;
initFabHandlers();

export { initFabHandlers };
