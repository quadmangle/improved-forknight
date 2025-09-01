const test = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const fs = require('node:fs');
const path = require('node:path');
const htmlPath = path.join(__dirname, '..', 'fabs', 'chatbot.html');
const jsPath = path.join(__dirname, '..', 'fabs', 'js', 'chattia.js');
const dragJsPath = path.join(__dirname, '..', 'fabs', 'js', 'cojoin.js');
const cssPath = path.join(__dirname, '..', 'fabs', 'css', 'chatbot.css');
const html = fs.readFileSync(htmlPath, 'utf8');
const script = fs.readFileSync(jsPath, 'utf8');
const dragScript = fs.readFileSync(dragJsPath, 'utf8');
const style = fs.readFileSync(cssPath, 'utf8');
const antibotJs = fs.readFileSync(path.join(__dirname, '..', 'js', 'antibot.js'), 'utf8');
const hpHtml = fs.readFileSync(path.join(__dirname, '..', 'security', 'honeypots.html'), 'utf8');
const utilsJs = fs.readFileSync(path.join(__dirname, '..', 'js', 'utils.js'), 'utf8');
const langThemeJs = fs.readFileSync(path.join(__dirname, '..', 'js', 'langtheme.js'), 'utf8');
test('Chattia chatbot basic interactions', async () => {
  const dom = new JSDOM(`<body></body>`, { url: 'https://www.opsonlinesupport.com', runScripts: 'dangerously' });
  const { window } = dom;
  const document = window.document;
  window.innerWidth = 1024;
  const styleEl = document.createElement('style');
  styleEl.textContent = style;
  document.head.appendChild(styleEl);
  window.fetch = async (url, opts) => {
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
  const brand = document.getElementById('brand');
  assert.ok(brand.querySelectorAll('.char').length > 0);
  const langCtrl = document.getElementById('langCtrl');
  const input = document.getElementById('chatbot-input');
  langCtrl.click();
  assert.strictEqual(document.documentElement.lang, 'es');
  langCtrl.click();
  assert.strictEqual(document.documentElement.lang, 'en');
  const themeCtrl = document.getElementById('themeCtrl');
    themeCtrl.click();
    assert.ok(document.documentElement.classList.contains('dark'));
    themeCtrl.click();
    assert.ok(!document.documentElement.classList.contains('dark'));
  const send = document.getElementById('chatbot-send');
  assert.ok(send.disabled);
  input.value = 'Hi';
  input.dispatchEvent(new window.Event('input', { bubbles: true }));
  assert.ok(!send.disabled);

  // honeypot triggers lock
  let alerted = false;
  window.alert = () => { alerted = true; };
  document.getElementById('hp_check').dispatchEvent(new window.Event('click', { bubbles: true }));
  assert.ok(alerted);
  assert.ok(send.disabled);

  // start fresh session
  document.querySelectorAll('#chatbot-container').forEach(el => el.remove());
  document.querySelectorAll('#chat-open-btn').forEach(el => el.remove());
  await window.reloadChat();
  window.openChatbot();
  const minimizeBtn = document.getElementById('minimizeBtn');
  const container = document.getElementById('chatbot-container');
  const openBtn = document.getElementById('chat-open-btn');
  const header = document.getElementById('chatbot-header');
  assert.ok(document.body.classList.contains('drag-enabled'));
  container.style.left = '0px';
  container.style.top = '0px';
  header.dispatchEvent(new window.MouseEvent('mousedown', { clientX: 10, clientY: 10, bubbles: true }));
  document.dispatchEvent(new window.MouseEvent('mousemove', { clientX: 30, clientY: 30, bubbles: true }));
  document.dispatchEvent(new window.MouseEvent('mouseup', { bubbles: true }));
  assert.notStrictEqual(container.style.left, '0px');
  assert.notStrictEqual(container.style.top, '0px');
  minimizeBtn.click();
  assert.strictEqual(container.style.display, 'none');
  openBtn.click();
  assert.strictEqual(container.style.display, '');

  // message persists across reloads
  window.grecaptcha = { ready: cb => cb(), execute: async () => 'token' };
  const recaptchaScript = document.getElementById('recaptcha-script');
  if (recaptchaScript && recaptchaScript.onload) recaptchaScript.onload();
  const form = document.getElementById('chatbot-input-grid');
  const input2 = document.getElementById('chatbot-input');
  input2.value = 'Hello';
  input2.dispatchEvent(new window.Event('input', { bubbles: true }));
  form.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
  await new Promise(r => setTimeout(r,0));
  document.querySelectorAll('#chatbot-container').forEach(el => el.remove());
  document.querySelectorAll('#chat-open-btn').forEach(el => el.remove());
  await window.reloadChat();
  const logText = document.getElementById('chat-log').textContent;
  assert.ok(logText.includes('Hello'));
  const closeBtn = document.getElementById('chatbot-close');
  closeBtn.click();
  assert.strictEqual(document.getElementById('chatbot-container'), null);
});
