// This file contains the main logic for page-specific dynamic content and modals.

// Grab the translation data from langtheme.js (which is loaded first).
// The `translations` object contains all service card and modal data.
// We assume `translations` and `currentLanguage` are globally available after langtheme.js loads.


function createModal(serviceKey, lang) {
  const modalRoot = document.getElementById('modal-root');
  const serviceData = translations.services[serviceKey];
  const modalData = serviceData[lang].modal;
  if (!modalData) return;
  // Create modal content
  const modalContent = document.createElement('div');
  modalContent.className = 'ops-modal';

  // Build the modal HTML with new buttons in the footer
  modalContent.innerHTML = `
    <button class="close-modal" aria-label="Close modal">×</button>
    <div class="modal-header">
      <img src="${serviceData.img}" alt="${modalData.imgAlt}" class="modal-img">
      <h3 class="modal-title">${modalData.title}</h3>
    </div>
    <div class="modal-content-body">
      <p>${modalData.content}</p>
      <ul class="modal-features">
        ${modalData.features.map(feature => `<li>${feature}</li>`).join('')}
      </ul>
    </div>
    <div class="modal-actions">
      <a href="${serviceData.learn}" class="modal-btn learn-more" data-key="modal-learn-more"></a>
    </div>
  `;

  // Append modal directly to the modal root
  modalRoot.appendChild(modalContent);

  // Make the modal draggable
  window.appUtils.makeDraggable(modalContent);

  // Update button text with translations
  updateModalContent(modalContent, lang);

  // Add event listener to close button
  modalContent.querySelector('.close-modal').addEventListener('click', closeModal);

  // Close modal on Escape key
  const handleKeydown = (event) => {
    if (event.key === 'Escape') {
      closeModal();
    }
  };
  document.addEventListener('keydown', handleKeydown);

  // Close modal when clicking outside of it
  function handleOutsideClick(event) {
    if (!modalContent.contains(event.target)) {
      closeModal();
    }
  }
  document.addEventListener('click', handleOutsideClick);
  function closeModal() {
    modalRoot.innerHTML = '';
    document.removeEventListener('click', handleOutsideClick);
    document.removeEventListener('keydown', handleKeydown);
  }
}


// Helper function to update content inside the modal after creation
function updateModalContent(modalElement, lang) {
  const elements = modalElement.querySelectorAll('[data-key]');
  elements.forEach(el => {
    const key = el.getAttribute('data-key');
    const translation = translations[lang][key];
    if (translation) {
      el.textContent = translation;
    }
  });
}


document.addEventListener('DOMContentLoaded', () => {
  const navToggle = document.querySelector('.nav-menu-toggle');
  const navLinks = document.querySelector('.nav-links');
  // Backdrop element shown behind the mobile menu; clicking it closes the menu
  const navBackdrop = document.querySelector('.nav-backdrop');
  let navLabel = 'Menu';
  let closeLabel = 'Close navigation menu';
  if (navToggle) {
    const ariaKey = navToggle.getAttribute('data-aria-label-key');
    const langData = (typeof translations !== 'undefined' && translations[currentLanguage]) || {};
    navLabel = langData[ariaKey] || 'Menu';
    closeLabel = langData['aria-close-menu'] || 'Close navigation menu';
    navToggle.setAttribute('aria-label', navLabel);

    const updateToggleVisibility = () => {
      navToggle.style.display = window.innerWidth <= 768 ? 'block' : 'none';
    };
    updateToggleVisibility();
    window.addEventListener('resize', updateToggleVisibility);
  }
  if (navToggle && navLinks) {
    let lastFocusedElement;
    let firstFocusable;
    let lastFocusable;

    function trapFocus(e) {
      if (e.key === 'Tab') {
        if (e.shiftKey) {
          if (document.activeElement === firstFocusable) {
            e.preventDefault();
            lastFocusable.focus();
          }
        } else {
          if (document.activeElement === lastFocusable) {
            e.preventDefault();
            firstFocusable.focus();
          }
        }
      } else if (e.key === 'Escape') {
        closeMenu();
      }
    }

    function handleClickOutside(e) {
      // Close the menu when clicking outside the nav links or toggle
      if (!navLinks.contains(e.target) && !navToggle.contains(e.target)) {
        closeMenu();
      }
    }

    function openMenu() {
      navLinks.classList.add('open');
      navToggle.setAttribute('aria-expanded', 'true');
      navToggle.setAttribute('aria-label', closeLabel);
      const icon = navToggle.querySelector('i');
      if (icon) {
        icon.classList.remove('fa-bars');
        icon.classList.add('fa-xmark');
      }
      if (navBackdrop) {
        navBackdrop.classList.add('open');
        navBackdrop.removeAttribute('hidden');
        navBackdrop.addEventListener('click', closeMenu); // Clicking the overlay closes the menu
      }
      const focusable = navLinks.querySelectorAll('a, button');
      firstFocusable = focusable[0];
      lastFocusable = focusable[focusable.length - 1];
      lastFocusedElement = document.activeElement;
      if (firstFocusable) {
        firstFocusable.focus();
      }
      document.addEventListener('keydown', trapFocus);
      // Delay adding outside click handler so the opening click doesn't trigger it
      setTimeout(() => document.body.addEventListener('click', handleClickOutside));
    }

    function closeMenu() {
      navLinks.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
      navToggle.setAttribute('aria-label', navLabel);
      const icon = navToggle.querySelector('i');
      if (icon) {
        icon.classList.add('fa-bars');
        icon.classList.remove('fa-xmark');
      }
      if (navBackdrop) {
        navBackdrop.classList.remove('open');
        navBackdrop.setAttribute('hidden', '');
        navBackdrop.removeEventListener('click', closeMenu);
      }
      document.removeEventListener('keydown', trapFocus);
      document.body.removeEventListener('click', handleClickOutside);
      if (lastFocusedElement) {
        lastFocusedElement.focus();
      }
    }

    navToggle.addEventListener('click', () => {
      const isOpen = navLinks.classList.contains('open');
      if (isOpen) {
        closeMenu();
      } else {
        openMenu();
      }
    });

    navLinks.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        if (window.innerWidth <= 768) {
          closeMenu();
        }
      });
    });
  }

  // --- Learn More Links & Buttons ---
  // langtheme.js runs its own DOMContentLoaded handler before this script,
  // so translated text is available when wiring up the links.
  const learnMoreEls = document.querySelectorAll('.learn-more');
  learnMoreEls.forEach(el => {
    const card = el.closest('[data-service-key]');
    if (card) {
      const serviceKey = card.getAttribute('data-service-key');
      const service = translations.services[serviceKey];
      if (service && service.learn) {
        el.setAttribute('href', service.learn);
        // Make entire card act as a link to the service page
        card.setAttribute('role', 'link');
        card.tabIndex = 0;
        const navigate = () => { window.location.href = service.learn; };
        card.addEventListener('click', e => {
          if (!e.target.closest('.learn-more')) {
            navigate();
          }
        });
        card.addEventListener('keydown', e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            navigate();
          }
        });
      }
      return;
    }

    const target = el.getAttribute('data-target');
    if (target) {
      el.addEventListener('click', e => {
        e.preventDefault();
        createModal(target, currentLanguage);
      });
    }
  });

  const contactButtons = document.querySelectorAll('.contact-button');
  contactButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const fabContact = document.getElementById('fab-contact');
      if (fabContact) {
        fabContact.click();
      }
    });
  });

});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then(registration => {
        console.log('ServiceWorker registration successful with scope: ', registration.scope);
      })
      .catch(error => {
        console.log('ServiceWorker registration failed: ', error);
      });
  });
}
