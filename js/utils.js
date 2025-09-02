(function() {
  'use strict';

  /**
   * Sanitizes input to prevent malicious code injection.
   * This is a simple client-side check and not a replacement for server-side validation.
   * It uses DOMPurify if available, otherwise falls back to a regex and DOM-based approach.
   * @param {string} input The string to sanitize.
   * @returns {string} The sanitized string.
   */
  function sanitizeInput(input) {
    // 1. Ensure input is a string
    if (typeof input !== 'string' || !input) {
      return '';
    }

    // 2. Use DOMPurify if it's loaded and available. This is the preferred method.
    if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
      return window.DOMPurify.sanitize(input, { USE_PROFILES: { html: false } }); // Disallow all HTML
    }

    // 3. If DOMPurify is not available, use a fallback sanitization method.
    console.warn('DOMPurify not found. Falling back to DOM-based sanitization.');
    // Use the browser's own parser to strip any HTML tags and neutralize content.
    // .textContent ensures no HTML is interpreted, including malformed and invalid tags.
    if (typeof document !== 'undefined') {
      try {
        const div = document.createElement('div');
        div.textContent = input;
        // By reading textContent back, we ensure no HTML is interpreted, including invalid tags.
        return div.textContent;
      } catch (e) {
        // Fallback for environments without a DOM or with other issues.
        // Remove any remaining tags (repeatedly) in environments without DOM.
        let stripped = input;
        let prevStripped;
        do {
          prevStripped = stripped;
          stripped = stripped.replace(/<[^>]*>/g, '');
        } while (stripped !== prevStripped);
        return stripped;
      }
    }

    // Final fallback for non-browser environments.
    // Remove any remaining tags (repeatedly) as final fallback.
    let stripped = cleaned;
    let prevStripped;
    do {
      prevStripped = stripped;
      stripped = stripped.replace(/<[^>]*>/g, '');
    } while (stripped !== prevStripped);
    return stripped;
  }

  /**
   * Enables draggable functionality for modals on large screens.
   * @param {HTMLElement} modal The modal element to make draggable.
   */
  function makeDraggable(modal) {
    // Only make draggable on larger screens where there is enough space.
    if (window.innerWidth < 768) {
      return;
    }

    let isDragging = false;
    let offsetX, offsetY;
    const modalHeader = modal.querySelector('.modal-header') || modal.querySelector('#chatbot-header');
    if (!modalHeader) return;
    function onMouseMove(e) {
      if (!isDragging) return;
      e.preventDefault();
      const newX = e.clientX - offsetX;
      const newY = e.clientY - offsetY;
      modal.style.left = `${newX}px`;
      modal.style.top = `${newY}px`;
      modal.style.transform = 'none';
    }

    function onMouseUp() {
      if (!isDragging) return;
      isDragging = false;
      modal.style.cursor = 'move';
      modal.style.transition = 'transform 0.3s ease'; // Re-enable transition
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    }

    modalHeader.addEventListener('mousedown', (e) => {
      // Avoid initiating drag when interacting with header controls
      if (e.target.closest && e.target.closest('button, a, input, select, textarea, .ctrl')) {
        return;
      }
      isDragging = true;
      offsetX = e.clientX - modal.getBoundingClientRect().left;
      offsetY = e.clientY - modal.getBoundingClientRect().top;
      modal.style.cursor = 'grabbing';
      modal.style.transition = 'none'; // Disable transition while dragging
      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
    });
  }

  // Expose the functions to the global scope
  window.appUtils = {
    sanitizeInput: sanitizeInput,
    makeDraggable: makeDraggable
  };

  // Provide a global helper for draggable modals used by cojoinlistener.js
  window.initDraggableModal = function(modal) {
    if (modal && window.appUtils && typeof window.appUtils.makeDraggable === 'function') {
      window.appUtils.makeDraggable(modal);
    }
  };
})();
