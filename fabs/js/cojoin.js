/**
 * fabs/js/cojoin.js
 *
 * This script contains the logic for both the Contact Us and Join Us forms.
 * It handles form submission, security checks (honeypot, malicious code),
 * and the dynamic form fields for the Join form.
 */

function initCojoinForms() {
  const contactForm = document.getElementById('contactForm');
  const joinForm = document.getElementById('joinForm');
  const CONTACT_WORKER_URL = window.CONTACT_WORKER_URL || 'https://ops-contact-intake.pure-sail-sole.workers.dev';
  const JOIN_WORKER_URL = window.JOIN_WORKER_URL || 'https://ops-join-intake.pure-sail-sole.workers.dev';

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
    sanitizedData.nonce = crypto.randomUUID();
    alert('Contact form submission disabled.');
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
    sanitizedData.nonce = crypto.randomUUID();
    alert('Join form submission disabled.');
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
