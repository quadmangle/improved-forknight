const test = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

test('learn-more buttons link to service pages', () => {
  const html = `<!DOCTYPE html><html><body>
    <div id="modal-root"></div>
    <section id="cards-section">
      <div class="card" data-service-key="cc">
        <a class="learn-more">Learn More</a>
      </div>
    </section>
  </body></html>`;

  const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'https://www.opsonlinesupport.com/' });
  const { window } = dom;
  window.fetch = async () => ({
    ok: true,
    json: async () => ({ token: 'mock-csrf-token' }),
  });
  window.currentLanguage = 'en';
  window.translations = {
    services: {
      cc: { learn: 'contact-center.html' }
    }
  };

  const script = fs.readFileSync(path.join(__dirname, '../js/main.js'), 'utf8');
  window.eval(script);

  let called = false;
  window.createModal = () => { called = true; };

  window.document.dispatchEvent(new window.Event('DOMContentLoaded', { bubbles: true }));

  const btn = window.document.querySelector('.learn-more');
  assert.equal(btn.getAttribute('href'), 'contact-center.html');
  btn.click();
  assert.equal(called, false, 'click should not open modal');
});

