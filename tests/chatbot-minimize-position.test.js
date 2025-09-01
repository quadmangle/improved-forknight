const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const root = path.resolve(__dirname, '..');
const antibotJs = fs.readFileSync(path.join(root, 'js', 'antibot.js'), 'utf8');
const hpHtml = fs.readFileSync(path.join(root, 'security', 'honeypots.html'), 'utf8');
const utilsJs = fs.readFileSync(path.join(root, 'js', 'utils.js'), 'utf8');
const langThemeJs = fs.readFileSync(path.join(root, 'js', 'langtheme.js'), 'utf8');

test('chatbot minimize positions open button above FAB by 10px and centers horizontally', async () => {
    const html = fs.readFileSync(path.join(root, 'fabs', 'chatbot.html'), 'utf8');
    const chatJs = fs.readFileSync(path.join(root, 'fabs', 'js', 'chattia.js'), 'utf8');
    const dragJs = fs.readFileSync(path.join(root, 'fabs', 'js', 'cojoin.js'), 'utf8');
    const chatCss = fs.readFileSync(path.join(root, 'fabs', 'css', 'chatbot.css'), 'utf8');
    const fabCss = fs.readFileSync(path.join(root, 'fabs', 'css', 'cojoin.css'), 'utf8');

  const dom = new JSDOM('<!DOCTYPE html><body></body>', {
    url: 'https://www.opsonlinesupport.com',
    runScripts: 'dangerously'
  });
  const { window } = dom;
  const { document } = window;

  const styleEl = document.createElement('style');
  styleEl.textContent = chatCss + fabCss;
  document.head.appendChild(styleEl);

  // Basic fetch mocks
  window.fetch = async (url) => {
    if (url.includes('chatbot.html')) {
      return { text: async () => html };
    }
    if (url.includes('security/honeypots.html')) {
      return { ok: true, text: async () => hpHtml };
    }
    if (url.includes('honeypot') || url.includes('end-session')) {
      return {};
    }
    return { json: async () => ({ reply: 'ok' }) };
  };
  window.alert = () => {};
  window.grecaptcha = { ready: cb => cb(), execute: async () => 'token' };
    window.eval(utilsJs);
    window.eval(antibotJs);
    window.eval(langThemeJs);
    window.eval(dragJs);

  // Create FAB structure
  const fabContainer = document.createElement('div');
  fabContainer.className = 'fab-container';
  const fabMain = document.createElement('button');
  fabMain.className = 'fab-main';
  fabMain.style.height = '60px';
  fabMain.style.width = '60px';
  fabContainer.appendChild(fabMain);
  document.body.appendChild(fabContainer);

    window.eval(chatJs);
  await window.reloadChat();

  const openBtn = document.getElementById('chat-open-btn');
  const minimizeBtn = document.getElementById('minimizeBtn');

  openBtn.click();
  minimizeBtn.click();

  const fabBottom = parseInt(window.getComputedStyle(fabContainer).bottom, 10);
  const fabRight = parseInt(window.getComputedStyle(fabContainer).right, 10);
  const fabHeight = parseInt(window.getComputedStyle(fabMain).height, 10);
  const fabWidth = parseInt(window.getComputedStyle(fabMain).width, 10);
  const btnWidth = parseInt(window.getComputedStyle(openBtn).width, 10);
  const expectedBottom = fabBottom + fabHeight + 10;
  const expectedRight = fabRight + (fabWidth - btnWidth) / 2;
  const actualBottom = parseInt(window.getComputedStyle(openBtn).bottom, 10);
  const actualRight = parseInt(window.getComputedStyle(openBtn).right, 10);
  assert.strictEqual(actualBottom, expectedBottom);
  assert.strictEqual(actualRight, expectedRight);
  window.cleanupChatbot();
});

test('open button repositions correctly on reload when state is minimized', async () => {
    const html = fs.readFileSync(path.join(root, 'fabs', 'chatbot.html'), 'utf8');
    const chatJs = fs.readFileSync(path.join(root, 'fabs', 'js', 'chattia.js'), 'utf8');
    const dragJs = fs.readFileSync(path.join(root, 'fabs', 'js', 'cojoin.js'), 'utf8');
    const chatCss = fs.readFileSync(path.join(root, 'fabs', 'css', 'chatbot.css'), 'utf8');
    const fabCss = fs.readFileSync(path.join(root, 'fabs', 'css', 'cojoin.css'), 'utf8');

  const dom = new JSDOM('<!DOCTYPE html><body></body>', {
    url: 'https://www.opsonlinesupport.com',
    runScripts: 'dangerously'
  });
  const { window } = dom;
  const { document } = window;

  const styleEl = document.createElement('style');
  styleEl.textContent = chatCss + fabCss;
  document.head.appendChild(styleEl);

  window.fetch = async (url) => {
    if (url.includes('chatbot.html')) {
      return { text: async () => html };
    }
    if (url.includes('security/honeypots.html')) {
      return { ok: true, text: async () => hpHtml };
    }
    if (url.includes('honeypot') || url.includes('end-session')) {
      return {};
    }
    return { json: async () => ({ reply: 'ok' }) };
  };
  window.alert = () => {};

  const fabContainer = document.createElement('div');
  fabContainer.className = 'fab-container';
  const fabMain = document.createElement('button');
  fabMain.className = 'fab-main';
  fabMain.style.height = '60px';
  fabMain.style.width = '60px';
  fabContainer.appendChild(fabMain);
  document.body.appendChild(fabContainer);

  window.sessionStorage.setItem('chatState', 'minimized');
  window.grecaptcha = { ready: cb => cb(), execute: async () => 'token' };
    window.eval(utilsJs);
    window.eval(antibotJs);
    window.eval(langThemeJs);
    window.eval(dragJs);
    window.eval(chatJs);
  await window.reloadChat();

  const openBtn = document.getElementById('chat-open-btn');

  const fabBottom = parseInt(window.getComputedStyle(fabContainer).bottom, 10);
  const fabRight = parseInt(window.getComputedStyle(fabContainer).right, 10);
  const fabHeight = parseInt(window.getComputedStyle(fabMain).height, 10);
  const fabWidth = parseInt(window.getComputedStyle(fabMain).width, 10);
  const btnWidth = parseInt(window.getComputedStyle(openBtn).width, 10);
  const expectedBottom = fabBottom + fabHeight + 10;
  const expectedRight = fabRight + (fabWidth - btnWidth) / 2;
  const actualBottom = parseInt(window.getComputedStyle(openBtn).bottom, 10);
  const actualRight = parseInt(window.getComputedStyle(openBtn).right, 10);
  assert.strictEqual(actualBottom, expectedBottom);
  assert.strictEqual(actualRight, expectedRight);
  window.cleanupChatbot();
});

