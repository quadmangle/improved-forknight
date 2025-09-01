const test = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const fs = require('node:fs');
const path = require('node:path');

const htmlPath = path.join(__dirname, '..', 'fabs', 'chatbot.html');
const jsPath = path.join(__dirname, '..', 'fabs', 'js', 'chattia.js');
const dragJsPath = path.join(__dirname, '..', 'fabs', 'js', 'cojoin.js');
const cssPath = path.join(__dirname, '..', 'fabs', 'css', 'chatbot.css');
const antibotJs = fs.readFileSync(path.join(__dirname, '..', 'js', 'antibot.js'), 'utf8');
const utilsJs = fs.readFileSync(path.join(__dirname, '..', 'js', 'utils.js'), 'utf8');
const langThemeJs = fs.readFileSync(path.join(__dirname, '..', 'js', 'langtheme.js'), 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const script = fs.readFileSync(jsPath, 'utf8');
const dragScript = fs.readFileSync(dragJsPath, 'utf8');
const style = fs.readFileSync(cssPath, 'utf8');
const hpHtml = fs.readFileSync(path.join(__dirname, '..', 'security', 'honeypots.html'), 'utf8');

test('Chatbot header controls and send button work', async () => {
  const dom = new JSDOM(`<body></body>`, { url: 'https://www.opsonlinesupport.com', runScripts: 'dangerously' });
  const { window } = dom;
  const document = window.document;
  window.innerWidth = 1024;
  const styleEl = document.createElement('style');
  styleEl.textContent = style;
  document.head.appendChild(styleEl);
  window.fetch = async (url) => {
    if (url && url.includes('chatbot.html')) {
      return { text: async () => html };
    }
    if (url && url.includes('security/honeypots.html')) {
      return { ok: true, text: async () => hpHtml };
    }
    if (url && url.includes('honeypot')) {
      return {};
    }
    if (url && url.includes('end-session')) {
      return {};
    }
    return { json: async () => ({ reply: 'ok' }) };
  };
  window.alert = () => {};
  window.grecaptcha = { ready: cb => cb(), execute: async () => 'token' };
  window.eval(utilsJs);
  window.eval(antibotJs);
  window.eval(langThemeJs);
  window.eval(dragScript);
  window.eval(script);

  await window.reloadChat();
  window.openChatbot();

  const langCtrl = document.getElementById('langCtrl');
  langCtrl.click();
  assert.strictEqual(langCtrl.textContent, 'EN');

  const themeCtrl = document.getElementById('themeCtrl');
  const initialTheme = themeCtrl.textContent;
  themeCtrl.click();
  assert.notStrictEqual(themeCtrl.textContent, initialTheme);

  const input = document.getElementById('chatbot-input');
  input.value = 'hi';
  input.dispatchEvent(new window.Event('input'));
  document.getElementById('chatbot-send').click();
  const messages = [...document.querySelectorAll('#chat-log .chat-msg.user')];
  assert.ok(messages.some(m => m.textContent === 'hi'));

  document.getElementById('minimizeBtn').click();
  assert.strictEqual(document.getElementById('chatbot-container').style.display, 'none');
  window.openChatbot();
  document.getElementById('chatbot-close').click();
  assert.strictEqual(document.getElementById('chatbot-container'), null);
});
