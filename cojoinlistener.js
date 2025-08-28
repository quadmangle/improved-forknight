/**
 * cojoinlistener.js
 *
 * This script creates and manages the Floating Action Buttons (FABs)
 * for the Contact, Join, and Chatbot modals. It handles the toggle
 * logic and dynamically loads the modal content from the 'fabs' directory.
 */

document.addEventListener('DOMContentLoaded', () => {

  const body = document.body;

  // Create the FAB container and buttons
  const fabContainer = document.createElement('div');
  fabContainer.className = 'fab-container';
  body.appendChild(fabContainer);

  const fabMain = document.createElement('button');
  fabMain.className = 'fab-main';
  fabMain.innerHTML = '<i class="fas fa-plus"></i>';
  fabContainer.appendChild(fabMain);

  const fabOptions = document.createElement('div');
  fabOptions.className = 'fab-options';
  fabContainer.appendChild(fabOptions);

  const contactFab = createFabOption('contact', '<i class="fa fa-envelope"></i>', 'Contact Us');
  const joinFab = createFabOption('join', '<i class="fa fa-user-plus"></i>', 'Join Us');
  const chatbotFab = createFabOption('chatbot', '<i class="fa fa-comments"></i>', 'Chatbot Chattia');

  fabOptions.appendChild(contactFab);
  fabOptions.appendChild(joinFab);
  fabOptions.appendChild(chatbotFab);

  let activeModal = null;
  let overlay = null;
  // Track the element that was focused before a modal opened so we can
  // restore focus when the modal closes.
  let lastFocused = null;

  window.hideActiveFabModal = () => {
    if (activeModal) {
      hideModal(activeModal);
    }
  };

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && activeModal) {
      hideModal(activeModal);
    }
  });

  // Main FAB click handler
  fabMain.addEventListener('click', () => {
    fabContainer.classList.toggle('open');
    // Removed shine animation to prevent spinning effect on click
    // fabMain.classList.add('shine');
    // setTimeout(() => {
    //   fabMain.classList.remove('shine');
    // }, 600);
    // If FABs close, also close the active modal
    if (!fabContainer.classList.contains('open') && activeModal) {
      hideModal(activeModal);
    }
  });

  // Individual FAB click handlers
  contactFab.addEventListener('click', () => {
    showModal('contact');
  });

  joinFab.addEventListener('click', () => {
    showModal('join');
  });

  chatbotFab.addEventListener('click', () => {
    showModal('chatbot');
  });

  /**
   * Creates a single FAB option button.
   * @param {string} id The unique ID for the button.
   * @param {string} icon The HTML for the Font Awesome icon.
   * @param {string} title The title/aria-label for accessibility.
   * @returns {HTMLButtonElement} The created button element.
   */
  function createFabOption(id, icon, title) {
    const button = document.createElement('button');
    button.className = 'fab-option';
    button.id = `fab-${id}`;
    button.innerHTML = icon;
    button.title = title;
    button.setAttribute('aria-label', title);
    return button;
  }

  /**
   * Basic HTML sanitization. Uses DOMPurify when available and falls back to a
   * minimal DOM-based sanitizer when it is not. The fallback strips potentially
   * dangerous elements (e.g., <script>, <iframe>, <object>) to avoid injecting
   * executable code while still allowing the FAB modals to render.
   * @param {string} dirty The HTML string to sanitize.
   * @returns {string} A sanitized HTML string.
   */
  function sanitizeHTML(dirty) {
    if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
      return window.DOMPurify.sanitize(dirty);
    }

    // Fallback: parse the HTML and strip scriptable elements.
    console.warn('DOMPurify is not available; using basic sanitization.');
    const parser = new DOMParser();
    const doc = parser.parseFromString(dirty, 'text/html');
    doc.querySelectorAll('script, iframe, object').forEach(el => el.remove());
    return doc.body.innerHTML;
  }

  /**
   * Displays the specified modal, dynamically loading it if not already present.
   * @param {string} modalId The ID of the modal to show ('contact', 'join', or 'chatbot').
   */
  async function showModal(modalId) {
    const targetId = modalId === 'chatbot' ? 'chatbot-container' : `${modalId}-modal`;

    // Remember the currently focused element to restore later
    lastFocused = document.activeElement;

    // Hide any currently active modal before showing a new one
    if (activeModal && activeModal.id !== targetId) {
      hideModal(activeModal);
    }

    let modal = document.getElementById(targetId);
    if (modal) {
      if (modalId === 'chatbot') {
        if (window.openChatbot) { window.openChatbot(); }
      } else {
        modal.style.display = 'flex';
      }
      activeModal = modal;
    } else {
      // Dynamic loading logic: fetch HTML from 'fabs/' directory
      try {
        const url = `fabs/${modalId}.html`;
        const response = await fetch(url, { credentials: 'same-origin' });
        const responseURL = response.url || '';
        if (responseURL && typeof window !== 'undefined' && window.location) {
          const currentOrigin = window.location.origin;
          try {
            const resOrigin = new URL(responseURL, window.location.href).origin;
            if (currentOrigin && currentOrigin !== 'null' && resOrigin !== currentOrigin) {
              throw new Error('Cross-origin fetch blocked');
            }
          } catch (err) {
            console.error('URL parsing error:', err);
          }
        }
        const type = (response.headers && response.headers.get
          ? response.headers.get('Content-Type')
          : '') || '';
        if (type && !type.toLowerCase().startsWith('text/html')) {
          throw new Error(`Unexpected content type: ${type}`);
        }
        const htmlContent = await response.text();
        const sanitized = sanitizeHTML(htmlContent);
        const template = document.createElement('template');
        template.innerHTML = sanitized;

        const root = template.content || template;
        let openBtnEl;
        if (modalId === 'chatbot') {
          openBtnEl = root.querySelector('#chat-open-btn');
          modal = root.querySelector('#chatbot-container');
          if (openBtnEl && !document.getElementById('chat-open-btn')) {
            document.body.appendChild(openBtnEl);
          }
        } else {
          modal = root.querySelector('.modal-container');
        }
        if (modal) {
          if (modalId !== 'chatbot') {
            modal.id = targetId;
          }
          document.body.appendChild(modal);
          if (window.initCojoinForms) {
            try {
              window.initCojoinForms();
            } catch (err) {
              console.error('initCojoinForms failed:', err);
            }
          }
          if (modalId === 'chatbot') {
            if (window.initChatbot) { window.initChatbot(); }
            if (window.openChatbot) { window.openChatbot(); }
          } else {
            modal.style.display = 'flex';
          }
          activeModal = modal;

          // Add close button functionality
          const closeBtn = modal.querySelector('.modal-close');
          if (closeBtn) {
            closeBtn.addEventListener('click', () => hideModal(modal));
          }
        }
      } catch (error) {
        console.error(`Failed to load modal for ${modalId}:`, error);
      }
    }

    if (modal) {
      removeOverlay();
      if (modalId !== 'chatbot') {
        overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.addEventListener('click', () => hideModal(modal));
        document.body.appendChild(overlay);
      }

      // Initialize draggable on window load, then update on resize
      // This function is expected to be defined in fabs/js/cojoin.js
      if (window.initDraggableModal) {
        window.initDraggableModal(modal);
      }

      // Shift keyboard focus into the modal. For chatbot we focus the input;
      // otherwise focus the first interactive element.
      const focusTarget =
        modalId === 'chatbot'
          ? modal.querySelector('#chatbot-input')
          : modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (focusTarget && focusTarget.focus) {
        focusTarget.focus();
      }
    }

    fabContainer.classList.remove('open');
  }

  /**
   * Hides the specified modal.
   * @param {HTMLElement} modal The modal element to hide.
   */
  function hideModal(modal) {
    if (modal) {
      if (modal.id === 'chatbot-container' && typeof window.cleanupChatbot === 'function') {
        try {
          window.cleanupChatbot();
        } catch (err) {
          console.error('cleanupChatbot failed:', err);
        }
      }
      modal.style.display = 'none';
      activeModal = null;
    }
    removeOverlay();
    // Restore focus to the element that triggered the modal
    if (lastFocused && lastFocused.focus) {
      lastFocused.focus();
      lastFocused = null;
    }
  }

  function removeOverlay() {
    if (overlay) {
      if (overlay.remove) {
        overlay.remove();
      } else if (overlay.parentNode) {
        overlay.parentNode.removeChild(overlay);
      }
      overlay = null;
    }
  }

  // Handle window resizing to adjust draggable functionality
  window.addEventListener('resize', () => {
    if (activeModal && window.initDraggableModal) {
      window.initDraggableModal(activeModal);
    }
  });

});
