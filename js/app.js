(function () {
  "use strict";

  // ============================================================
  // State
  // ============================================================
  let articles = [];
  let filteredArticles = [];
  let isLoading = false;

  let searchQuery = "";
  let sortBy = "date-desc";
  let currentProduct = "all";
  let currentDomain = "all";
  let showBookmarksOnly = false;

  const bookmarks = new Set(
    JSON.parse(localStorage.getItem("mssecnews-bookmarks") || "[]")
  );

  const productColors = {
    "defender-xdr": "#7C3AED",
    "defender-endpoint": "#9333EA",
    "defender-identity": "#A855F7",
    "defender-cloud-apps": "#C084FC",
    "defender-office": "#D8B4FE",
    "defender-cloud": "#6366F1",
    sentinel: "#4F46E5",
    entra: "#2563EB",
    purview: "#0891B2",
    intune: "#0D9488",
    msrc: "#DC2626",
    "security-copilot": "#06B6D4",
    "ai-security": "#EC4899",
    "general-security": "#64748B",
  };

  const domainColors = {
    "identity-security": "#2563EB",
    "endpoint-security": "#9333EA",
    "email-security": "#D97706",
    "cloud-security": "#0891B2",
    "siem-xdr": "#4F46E5",
    "threat-intelligence": "#DC2626",
    "incident-response": "#B91C1C",
    "governance-compliance": "#0F766E",
    "vulnerability-management": "#EA580C",
    "security-operations": "#7C3AED",
    "ai-security": "#EC4899",
    "general-security": "#64748B",
  };

  // ============================================================
  // DOM
  // ============================================================
  const articlesGrid = document.getElementById("articles-grid");
  const loadingEl = document.getElementById("loading");
  const noResultsEl = document.getElementById("no-results");
  const searchInput = document.getElementById("search-input");
  const sortSelect = document.getElementById("sort-by");
  const dateFilter = document.getElementById("date-filter");
  const themeToggle = document.getElementById("theme-toggle");
  const filterPills = document.getElementById("filter-pills");
  const domainPills = document.getElementById("domain-pills");
  const showingCount = document.getElementById("showing-count");
  const lastUpdated = document.getElementById("last-updated");
  const totalCount = document.getElementById("total-count");
  const toastEl = document.getElementById("toast");
  const bookmarksToggle = document.getElementById("bookmarks-toggle");

  const escapeDiv = document.createElement("div");

  // ============================================================
  // Init
  // ============================================================
  async function init() {
    loadTheme();
    registerServiceWorker();
    setupEventListeners();
    await loadData();
  }

  // ============================================================
  // Service Worker
  // ============================================================
  function registerServiceWorker() {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("sw.js").catch(console.error);
    }
  }

  // ============================================================
  // Theme
  // ============================================================
  function loadTheme() {
    const saved = localStorage.getItem("mssecnews-theme") || "dark";

    document.documentElement.setAttribute("data-theme", saved);

    if (themeToggle) {
      themeToggle.textContent = saved === "dark" ? "☀️" : "🌙";
    }
  }

  function toggleTheme() {
    const current =
      document.documentElement.getAttribute("data-theme") || "dark";

    const next = current === "dark" ? "light" : "dark";

    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("mssecnews-theme", next);

    themeToggle.textContent = next === "dark" ? "☀️" : "🌙";
  }

  // ============================================================
  // Loading / UI State
  // ============================================================
  function showLoading(show) {
    isLoading = show;
    loadingEl.classList.toggle("visible", show);

    if (show) {
      noResultsEl.classList.remove("visible");
    }
  }

  function showNoResults(show) {
    noResultsEl.classList.toggle("visible", show);
  }

  // ============================================================
  // Data Loading
  // ============================================================
  async function loadData() {
    showLoading(true);

    try {
      const response = await fetch("data/feeds.json", {
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error("Failed to load feed data");
      }

      const data = await response.json();

      articles = data.articles || [];

      updateHeaderStats(data);
      renderProductFilters();
      renderDomainFilters();
      applyFilters();
    } catch (err) {
      console.error(err);

      articlesGrid.innerHTML = `
        <div style="grid-column:1/-1;text-align:center;padding:4rem;">
          <p style="font-size:1.3rem;">📡 No feed data available yet</p>
          <p>Run the feed workflow and refresh.</p>
        </div>
      `;
    } finally {
      showLoading(false);
    }
  }

  function updateHeaderStats(data) {
    totalCount.textContent = `${articles.length} articles`;

    if (data.lastUpdated) {
      const dt = new Date(data.lastUpdated);

      lastUpdated.textContent =
        "Last updated: " +
        dt.toLocaleString("en-GB", {
          weekday: "short",
          year: "numeric",
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });
    }
  }

  // ============================================================
  // Filters
  // ============================================================
  function applyFilters() {
    let result = [...articles];

    if (currentProduct !== "all") {
      result = result.filter((article) =>
        (article.products || []).some((p) => p.id === currentProduct)
      );
    }

    if (currentDomain !== "all") {
      result = result.filter((article) =>
        (article.domains || []).some((d) => d.id === currentDomain)
      );
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();

      result = result.filter(
        (article) =>
          article.title?.toLowerCase().includes(q) ||
          article.summary?.toLowerCase().includes(q) ||
          article.source?.toLowerCase().includes(q) ||
          article.author?.toLowerCase().includes(q) ||
          article.source_group?.toLowerCase().includes(q)
      );
    }

    const dateVal = dateFilter.value;

    if (dateVal !== "all") {
      const now = new Date();
      const cutoff = new Date();

      switch (dateVal) {
        case "today":
          cutoff.setHours(0, 0, 0, 0);
          break;
        case "week":
          cutoff.setDate(now.getDate() - 7);
          break;
        case "month":
          cutoff.setMonth(now.getMonth() - 1);
          break;
      }

      result = result.filter(
        (article) => new Date(article.published) >= cutoff
      );
    }

    if (showBookmarksOnly) {
      result = result.filter((article) => bookmarks.has(article.link));
    }

    switch (sortBy) {
      case "date-asc":
        result.sort((a, b) => new Date(a.published) - new Date(b.published));
        break;

      case "source":
        result.sort((a, b) => a.source.localeCompare(b.source));
        break;

      default:
        result.sort((a, b) => new Date(b.published) - new Date(a.published));
    }

    filteredArticles = result;

    showingCount.textContent = `Showing ${result.length} of ${articles.length} articles`;

    renderArticles();
  }

  function renderProductFilters() {
    const counts = {};

    articles.forEach((article) => {
      (article.products || []).forEach((product) => {
        if (!counts[product.id]) {
          counts[product.id] = {
            name: product.name,
            count: 0,
          };
        }

        counts[product.id].count++;
      });
    });

    let html = `
      <button class="pill active" data-product="all">
        All Products <span class="count">${articles.length}</span>
      </button>
    `;

    Object.entries(counts)
      .sort((a, b) => a[1].name.localeCompare(b[1].name))
      .forEach(([id, product]) => {
        html += `
          <button class="pill" data-product="${id}">
            ${escapeHtml(product.name)}
            <span class="count">${product.count}</span>
          </button>
        `;
      });

    filterPills.innerHTML = html;
  }

  function renderDomainFilters() {
    const counts = {};

    articles.forEach((article) => {
      (article.domains || []).forEach((domain) => {
        if (!counts[domain.id]) {
          counts[domain.id] = {
            name: domain.name,
            count: 0,
          };
        }

        counts[domain.id].count++;
      });
    });

    let html = `
      <button class="pill active" data-domain="all">
        All Domains <span class="count">${articles.length}</span>
      </button>
    `;

    Object.entries(counts)
      .sort((a, b) => a[1].name.localeCompare(b[1].name))
      .forEach(([id, domain]) => {
        html += `
          <button class="pill" data-domain="${id}">
            ${escapeHtml(domain.name)}
            <span class="count">${domain.count}</span>
          </button>
        `;
      });

    domainPills.innerHTML = html;
  }

  // ============================================================
  // Rendering
  // ============================================================
  function renderArticles() {
    if (isLoading) return;

    if (!filteredArticles.length) {
      articlesGrid.innerHTML = "";
      showNoResults(true);
      return;
    }

    showNoResults(false);

    articlesGrid.innerHTML = filteredArticles.map(renderCard).join("");
  }

  function renderCard(article) {
    const isBookmarked = bookmarks.has(article.link);

    const date = new Date(article.published);

    const dateStr = date.toLocaleDateString("en-GB");

    const productTags = (article.products || [])
      .map(
        (product) => `
        <span class="blog-tag" style="background:${productColors[product.id] || "#64748B"}22;color:${productColors[product.id] || "#64748B"};">
          ${escapeHtml(product.name)}
        </span>
      `
      )
      .join("");

    const domainTags = (article.domains || [])
      .slice(0, 2)
      .map(
        (domain) => `
        <span class="blog-tag" style="background:${domainColors[domain.id] || "#64748B"}22;color:${domainColors[domain.id] || "#64748B"};">
          ${escapeHtml(domain.name)}
        </span>
      `
      )
      .join("");

    return `
      <article class="article-card">
        <div class="card-header">
          <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
            ${productTags}
            ${domainTags}
          </div>
          <button
            class="bookmark-btn ${isBookmarked ? "bookmarked" : ""}"
            data-action="bookmark"
            data-link="${encodeURIComponent(article.link)}"
          >
            ${isBookmarked ? "⭐" : "☆"}
          </button>
        </div>

        <h3 class="article-title">
          <a href="${escapeHtml(article.link)}" target="_blank" rel="noopener">
            ${escapeHtml(article.title)}
          </a>
        </h3>

        <div class="article-meta">
          <span>📰 ${escapeHtml(article.source)}</span>
          <span>🏷️ ${escapeHtml(article.source_group)}</span>
          <span>📅 ${dateStr}</span>
        </div>

        <p class="article-summary">${escapeHtml(article.summary)}</p>
      </article>
    `;
  }

  function toggleBookmark(link) {
    if (bookmarks.has(link)) {
      bookmarks.delete(link);
      showToast("Bookmark removed");
    } else {
      bookmarks.add(link);
      showToast("⭐ Bookmarked");
    }

    localStorage.setItem(
      "mssecnews-bookmarks",
      JSON.stringify([...bookmarks])
    );

    applyFilters();
  }

  function showToast(message) {
    toastEl.textContent = message;
    toastEl.classList.add("visible");

    setTimeout(() => {
      toastEl.classList.remove("visible");
    }, 2500);
  }

  function escapeHtml(str) {
    if (!str) return "";
    escapeDiv.textContent = str;
    return escapeDiv.innerHTML;
  }

  function setupEventListeners() {
    let debounce;

    searchInput.addEventListener("input", (e) => {
      clearTimeout(debounce);

      debounce = setTimeout(() => {
        searchQuery = e.target.value.trim();
        applyFilters();
      }, 250);
    });

    sortSelect.addEventListener("change", (e) => {
      sortBy = e.target.value;
      applyFilters();
    });

    dateFilter.addEventListener("change", applyFilters);
    themeToggle.addEventListener("click", toggleTheme);

    bookmarksToggle.addEventListener("click", () => {
      showBookmarksOnly = !showBookmarksOnly;
      bookmarksToggle.classList.toggle("active", showBookmarksOnly);
      applyFilters();
    });

    filterPills.addEventListener("click", (e) => {
      const pill = e.target.closest("[data-product]");
      if (!pill) return;

      filterPills.querySelectorAll(".pill").forEach((p) => {
        p.classList.remove("active");
      });

      pill.classList.add("active");
      currentProduct = pill.dataset.product;
      applyFilters();
    });

    domainPills.addEventListener("click", (e) => {
      const pill = e.target.closest("[data-domain]");
      if (!pill) return;

      domainPills.querySelectorAll(".pill").forEach((p) => {
        p.classList.remove("active");
      });

      pill.classList.add("active");
      currentDomain = pill.dataset.domain;
      applyFilters();
    });

    articlesGrid.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-action]");
      if (!btn) return;

      if (btn.dataset.action === "bookmark") {
        toggleBookmark(decodeURIComponent(btn.dataset.link));
      }
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();