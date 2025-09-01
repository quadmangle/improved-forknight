document.addEventListener('DOMContentLoaded', () => {
  const searchButton = document.getElementById('search-button');
  const voiceSearchButton = document.getElementById('voice-search-button');
  const searchInput = document.getElementById('search-input');
  const searchResultsContainer = document.getElementById('search-results');
  let searchIndex = [];

  fetch('js/search-index.json')
    .then(response => response.json())
    .then(data => {
      searchIndex = data;
    });

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

  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SpeechRecognition) {
    const recognition = new SpeechRecognition();
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
  } else {
    voiceSearchButton.style.display = 'none';
  }
});
