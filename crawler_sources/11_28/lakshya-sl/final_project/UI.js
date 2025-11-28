let currentNewsPage = 1;
const newsPerPage = 10;

function showToast(message = "✅ Added to portfolio!") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  toast.classList.add("fade-in");

  setTimeout(() => {
    toast.classList.remove("fade-in");
    toast.classList.add("fade-out");
  }, 1500);

  setTimeout(() => {
    toast.classList.add("hidden");
    toast.classList.remove("fade-out");
  }, 2000);
}

function toggleChat() {
  const chat = document.getElementById('chatWindow');
  chat.style.display = chat.style.display === 'flex' ? 'none' : 'flex';
}

function sendMessage() {
  const input = document.getElementById('userInput');
  const chatBody = document.getElementById('chatBody');
  const typingIndicator = document.getElementById('typingIndicator');

  const message = input.value.trim();
  if (message === '') return;

  const userMsg = document.createElement('p');
  userMsg.innerHTML = `<strong>You:</strong> ${message}`;
  chatBody.appendChild(userMsg);
  input.value = '';
  chatBody.scrollTop = chatBody.scrollHeight;

  typingIndicator.style.display = 'block';

  setTimeout(() => {
    typingIndicator.style.display = 'none';
    const botMsg = document.createElement('p');
    botMsg.innerHTML = `<strong>Bot:</strong> Sorry, I'm currently unable to respond.`;
    chatBody.appendChild(botMsg);
    chatBody.scrollTop = chatBody.scrollHeight;
  }, 1500);
}

document.getElementById('userInput').addEventListener('keydown', function(event) {
  if (event.key === 'Enter') {
    event.preventDefault();
    sendMessage();
  }
});

function formatTimeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);
  let interval = Math.floor(seconds / 31536000);
  if (interval >= 1) return `${interval} year${interval === 1 ? '' : 's'} ago`;
  interval = Math.floor(seconds / 2592000);
  if (interval >= 1) return `${interval} month${interval === 1 ? '' : 's'} ago`;
  interval = Math.floor(seconds / 86400);
  if (interval >= 1) return `${interval} day${interval === 1 ? '' : 's'} ago`;
  interval = Math.floor(seconds / 3600);
  if (interval >= 1) return `${interval} hour${interval === 1 ? '' : 's'} ago`;
  interval = Math.floor(seconds / 60);
  if (interval >= 1) return `${interval} minute${interval === 1 ? '' : 's'} ago`;
  return `${Math.floor(seconds)} second${seconds === 1 ? '' : 's'} ago`;
}

async function loadTopStories(page = 1, limit = 10) {
  try {
    const response = await fetch(`http://localhost:5000/api/news?page=${page}&limit=${limit}`);
    const stories = await response.json();
    const storiesContainer = document.getElementById('storiesContent');
    if (page === 1) storiesContainer.innerHTML = '';

    stories.forEach(story => {
      const timeAgo = formatTimeAgo(new Date(story.publishedAt));
      const ticker = story.ticker || 'GEN';
      const storyEl = document.createElement('div');
      storyEl.className = 'story-card p-4 mb-4 rounded-lg bg-gray-800 hover:bg-gray-700 transition cursor-pointer';
      storyEl.innerHTML = `
        <div class="flex flex-col sm:flex-row gap-4">
          <img src="${story.imageUrl || 'https://via.placeholder.com/150'}"
              alt="news image"
              class="w-full sm:w-48 h-32 object-cover rounded-lg mb-2 sm:mb-0">
          <div class="flex flex-col justify-between">
            <div>
              <div class="flex justify-between items-start mb-2">
                <span class="text-xs text-gray-400">${timeAgo}</span>
                <span class="text-xs font-semibold bg-blue-500 px-2 py-1 rounded">${ticker}</span>
              </div>
              <h3 class="text-lg font-semibold mb-2">${story.title}</h3>
              <p class="text-sm text-gray-300 mb-2">${story.description || ''}</p>
            </div>
            <div class="flex justify-between items-center">
              <span class="text-xs text-gray-400">${story.source}</span>
              <a href="${story.url}" target="_blank" class="text-xs text-blue-400 hover:underline">Read more</a>
            </div>
          </div>
        </div>
      `;
      storiesContainer.appendChild(storyEl);
    });

    if (stories.length < limit) {
      document.getElementById('loadMoreStoriesBtn').style.display = 'none';
    }
  } catch (error) {
    console.error('Error loading stories:', error);
  }
}

function showSection(sectionId) {
  const sections = ['charting', 'portfolio', 'screener', 'technical', 'stories'];
  sections.forEach(id => document.getElementById(id).classList.add('hidden'));
  document.getElementById(sectionId).classList.remove('hidden');
  if (sectionId === 'portfolio') loadPortfolio();
  if (sectionId === 'charting') {
    loadTradingViewWidget();
    setupChartTradeForm();
  }
  if (sectionId === 'stories') loadTopStories();
  if (sectionId === 'screener') loadScreenerData();
}

function formatNumber(num) {
  if (!num || isNaN(num)) return "--";
  if (num >= 1e9) return (num / 1e9).toFixed(2) + "B";
  if (num >= 1e6) return (num / 1e6).toFixed(2) + "M";
  if (num >= 1e3) return (num / 1e3).toFixed(2) + "K";
  return num;
}

function formatCurrency(value, symbol = "$", isINR = false) {
  if (!value || isNaN(value)) return "--";
  if (value >= 1e12) return symbol + (value / 1e12).toFixed(2) + (isINR ? " L Cr" : "T");
  if (value >= 1e9) return symbol + (value / 1e9).toFixed(2) + (isINR ? " Cr" : "B");
  if (value >= 1e6) return symbol + (value / 1e6).toFixed(2) + (isINR ? " L" : "M");
  return symbol + value.toFixed(2);
}

document.getElementById('loadMoreStoriesBtn').addEventListener('click', () => {
  currentNewsPage++;
  loadTopStories(currentNewsPage);
});

['filterSector', 'filterChange', 'sortKey'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('change', () => {
    document.getElementById('screenerLoader').classList.remove('hidden');
    loadScreenerData();
  });
});

async function loadScreenerData() {
  document.getElementById('screenerLoader').classList.remove('hidden');
  try {
    const sector = document.getElementById('filterSector')?.value || '';
    const change = document.getElementById('filterChange')?.value || '';
    const sort = document.getElementById('sortKey')?.value || '';
    const queryParams = new URLSearchParams({ sector, change, sort });
    const res = await fetch(`http://localhost:5000/api/screener?${queryParams}`);
    const data = await res.json();
    const tbody = document.querySelector('#screenerTableBody');
    tbody.innerHTML = '';

    data.forEach(stock => {
      const row = document.createElement('tr');
      row.className = 'hover:bg-gray-700 transition';
      row.innerHTML = `
        <td class="p-3">${stock.ticker}</td>
        <td class="p-3">$${stock.price}</td>
        <td class="p-3 ${parseFloat(stock.change_percent) >= 0 ? 'text-green-400' : 'text-red-400'}">${stock.change_percent}%</td>
        <td class="p-3 ${stock.signal === 'Buy' ? 'text-blue-400' : 'text-red-400'}">${stock.signal}</td>
        <td class="p-3">${formatNumber(stock.volume)}</td>
        <td class="p-3">${formatCurrency(stock.market_cap)}</td>
        <td class="p-3">${stock.pe}</td>
        <td class="p-3">${stock.eps}</td>
        <td class="p-3">
          <button class="bg-blue-500 hover:bg-blue-600 text-white text-xs px-3 py-1 rounded buy-btn" data-stock='${JSON.stringify(stock)}'>BUY</button>
        </td>
      `;
      tbody.appendChild(row);
    });

    document.querySelectorAll('.buy-btn').forEach(button => {
      button.addEventListener('click', e => {
        const stock = JSON.parse(e.target.getAttribute('data-stock'));
        addToPortfolio(stock, 'Buy');
      });
    });
  } catch (err) {
    console.error('Error loading screener data:', err);
  } finally {
    document.getElementById('screenerLoader').classList.add('hidden');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadScreenerData();
});

setInterval(() => {
  if (!document.getElementById('screener').classList.contains('hidden')) {
    loadScreenerData();
  }
}, 60000);

function addToPortfolio(stock, orderMode, quantity = 1) {
  const table = document.getElementById('portfolioTableBody');
  const existingRow = Array.from(table.children).find(row => {
    const symbol = row.children[1]?.textContent;
    const mode = row.children[4]?.textContent;
    return symbol === stock.ticker && mode === orderMode;
  });

  if (existingRow) {
    const qtyCell = existingRow.children[5];
    const newQty = parseInt(qtyCell.textContent || '1') + parseInt(quantity);
    qtyCell.textContent = newQty;
    existingRow.children[9].textContent = new Date().toLocaleString();
  } else {
    const rowCount = table.querySelectorAll('tr').length + 1;
    const row = document.createElement('tr');
    row.className = 'hover:bg-gray-700 transition';
    row.innerHTML = `
      <td class="p-3">${rowCount}</td>
      <td class="p-3 text-blue-400">${stock.ticker}</td>
      <td class="p-3">${stock.ticker}</td>
      <td class="p-3">Market</td>
      <td class="p-3">${orderMode}</td>
      <td class="p-3">${quantity}</td>
      <td class="p-3">$${stock.price}</td>
      <td class="p-3 text-green-400">$${stock.price}</td>
      <td class="p-3 text-green-400">$0.00</td>
      <td class="p-3">${new Date().toLocaleString()}</td>
    `;
    table.appendChild(row);
  }
  showToast();
}

function setupChartTradeForm() {
  const form = document.getElementById('chartTradeForm');
  if (!form) return;

  form.addEventListener('submit', e => {
    e.preventDefault();
    const symbol = document.getElementById('chartSymbol').value;
    const quantity = parseInt(document.getElementById('chartQuantity').value);
    const type = document.getElementById('chartType').value;

    if (!symbol || isNaN(quantity) || quantity <= 0) return alert("Please enter valid data.");

    fetch(`http://localhost:5000/api/quote?symbol=${symbol}`)
  .then(res => res.json())
  .then(data => {
    if (!data || !data.price) throw new Error("Invalid data");
    const stock = {
      ticker: data.symbol,
      price: data.price
    };
    addToPortfolio(stock, type, quantity);
  })
  .catch(err => alert("Error fetching stock: " + err.message));

  });
}
