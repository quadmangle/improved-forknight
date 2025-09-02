document.addEventListener('DOMContentLoaded', () => {
  const searchButton = document.getElementById('search-button');
  const voiceSearchButton = document.getElementById('voice-search-button');
  const searchInput = document.getElementById('search-input');
  const searchResultsContainer = document.getElementById('search-results');

  // If the required elements are not present, exit early to avoid errors
  if (!searchButton || !searchInput || !searchResultsContainer) {
    return;
  }

  let searchIndex = [];

  const buildIndex = async () => {
    try {
      const res = await fetch('sitemap.xml');
      const xmlText = await res.text();
      const parser = new DOMParser();
      const xml = parser.parseFromString(xmlText, 'application/xml');
      const locs = Array.from(xml.querySelectorAll('loc'));
      await Promise.all(locs.map(async (locEl) => {
        const url = new URL(locEl.textContent, window.location.origin);
        const pageRes = await fetch(url.pathname);
        const html = await pageRes.text();
        const tmp = document.createElement('div');
        tmp.innerHTML = html;
        searchIndex.push({
          url: url.pathname.replace(/^\//, ''),
          content: tmp.textContent || ''
        });
      }));
    } catch (err) {
      console.error('Error building search index:', err);
    }
  };

  buildIndex();

  const performSearch = () => {
    const query = searchInput.value.toLowerCase().trim();
    if (!query) {
      searchResultsContainer.innerHTML = '';
      return;
    }

    const results = searchIndex.filter(page => page.content.toLowerCase().includes(query));

    if (results.length === 1) {
      window.location.href = results[0].url;
      return;
    }

    displayResults(results);
  };

  const displayResults = (results) => {
    if (results.length === 0) {
      searchResultsContainer.innerHTML = '<p>No results found.</p>';
      return;
    }

    const html = results.map(result => `
      <div class="result-item">
        <h3><a href="${result.url}">${result.url}</a></h3>
        <p>${result.content.substring(0, 150)}...</p>
      </div>
    `).join('');

    searchResultsContainer.innerHTML = html;
  };

  searchButton.addEventListener('click', performSearch);
  searchInput.addEventListener('keyup', (event) => {
    if (event.key === 'Enter') {
      performSearch();
    }
  });

  if ('webkitSpeechRecognition' in window && voiceSearchButton) {
    const recognition = new webkitSpeechRecognition();
    recognition.continuous = false;
    recognition.lang = 'en-US';
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;

    voiceSearchButton.addEventListener('click', () => {
      try {
        recognition.start();
      } catch (err) {
        console.error('Speech recognition start error:', err);
      }
    });

    recognition.onresult = (event) => {
      const transcript = event.results[0][0].transcript;
      searchInput.value = transcript;
      performSearch();
    };

    recognition.onerror = (event) => {
      console.error('Speech recognition error:', event.error);
    };
  } else if (voiceSearchButton) {
    voiceSearchButton.style.display = 'none';
  }
});
