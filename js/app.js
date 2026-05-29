(function () {
    "use strict";

    // ---------------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------------
    let articles = [];
    let filteredArticles = [];
    let isLoading = false;

    let searchQuery = "";
    let sortBy = "date-desc";
    let currentProduct = "all";
    let showBookmarksOnly = false;

    // Validate localStorage contents on load — ensure it's an array of
    // strings before trusting it and fail gracefully if the value is corrupt.
    const bookmarks = new Set(loadBookmarks());

    // ---------------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------------
    const ALLOWED_URL_SCHEMES = new Set(["https:", "http:"]);

    const MAX_SUMMARY_LENGTH = 2000; // guard against absurdly long feed content
    const MAX_TITLE_LENGTH = 500;

    const productColors = {
        "defender-xdr": "#7C3AED",
        "defender-endpoint": "#9333EA",
        "defender-identity": "#A855F7",
        "defender-cloud-apps": "#C084FC",
        "defender-office": "#D8B4FE",
        "defender-cloud": "#6366F1",
        "sentinel": "#4F46E5",
        "purview": "#0891B2",
        "security-copilot": "#06B6D4",
        "threat-intelligence": "#DC2626",
        "ai-security": "#EC4899",
        "aws-security": "#FF9900",
        "gcp-security": "#4285F4",
        "splunk-security": "#65A30D",
        "cisa-advisories": "#B91C1C",
        "ncsc-guidance": "#0F766E",
        "general-security": "#64748B",
    };

    // Allowlist of valid product IDs — rejects unexpected values injected via
    // feed data before they ever reach a data-* attribute or CSS style.
    const KNOWN_PRODUCT_IDS = new Set(Object.keys(productColors));

    // ---------------------------------------------------------------------------
    // DOM references
    // ---------------------------------------------------------------------------
    const articlesGrid = document.getElementById("articles-grid");
    const loadingEl = document.getElementById("loading");
    const noResultsEl = document.getElementById("no-results");
    const searchInput = document.getElementById("search-input");
    const sortSelect = document.getElementById("sort-by");
    const dateFilter = document.getElementById("date-filter");
    const themeToggle = document.getElementById("theme-toggle");
    const filterPills = document.getElementById("filter-pills");
    const showingCount = document.getElementById("showing-count");
    const lastUpdated = document.getElementById("last-updated");
    const totalCount = document.getElementById("total-count");
    const toastEl = document.getElementById("toast");
    const bookmarksToggle = document.getElementById("bookmarks-toggle");

    // ---------------------------------------------------------------------------
    // Initialisation
    // ---------------------------------------------------------------------------
    async function init() {
        loadTheme();
        registerServiceWorker();
        setupEventListeners();
        await loadData();
    }

    function registerServiceWorker() {
        if ("serviceWorker" in navigator) {
            navigator.serviceWorker.register("sw.js").catch(console.error);
        }
    }

    // ---------------------------------------------------------------------------
    // Theme
    // ---------------------------------------------------------------------------
    function loadTheme() {
        const saved = localStorage.getItem("securitynews-theme") || "dark";
        // Allowlist the value — only accept known themes, fall back to "dark".
        const theme = saved === "light" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", theme);
        if (themeToggle) {
            themeToggle.textContent = theme === "dark" ? "☀️" : "🌙";
        }
    }

    function toggleTheme() {
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem("securitynews-theme", next);
        themeToggle.textContent = next === "dark" ? "☀️" : "🌙";
    }

    // ---------------------------------------------------------------------------
    // Loading / empty states
    // ---------------------------------------------------------------------------
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

    // ---------------------------------------------------------------------------
    // Data loading
    // ---------------------------------------------------------------------------
    async function loadData() {
        showLoading(true);

        try {
            const response = await fetch("data/feeds.json", {
                cache: "no-store",
            });

            if (!response.ok) {
                throw new Error(`Failed to load feed data: ${response.status}`);
            }

            const data = await response.json();

            // Validate and sanitise every article coming from the feed before
            // storing it in state.  Anything that fails validation is dropped, so
            // malformed or poisoned feed entries never reach the DOM.
            articles = (data.articles || [])
                .filter(isValidArticle)
                .map(sanitiseArticle);

            showLoading(false);
            updateHeaderStats(data);
            renderProductFilters();
            applyFilters();
        } catch (err) {
            showLoading(false);
            console.error(err);

            // Build the error UI with DOM methods — no innerHTML with dynamic text.
            articlesGrid.innerHTML = "";
            const wrapper = document.createElement("div");
            wrapper.style.cssText = "grid-column:1/-1;text-align:center;padding:4rem;";
            const p1 = document.createElement("p");
            p1.style.fontSize = "1.3rem";
            p1.textContent = "📡 No feed data available yet";
            const p2 = document.createElement("p");
            p2.textContent = "Run the feed pipeline and refresh.";
            wrapper.append(p1, p2);
            articlesGrid.appendChild(wrapper);
        }
    }

    // ---------------------------------------------------------------------------
    // Article validation & sanitisation
    // ---------------------------------------------------------------------------

    /**
     * Returns true only if the article has the minimum required shape.
     * Drops anything that looks structurally wrong (e.g. non-string link field).
     */
    function isValidArticle(article) {
        if (!article || typeof article !== "object") return false;
        if (typeof article.link !== "string") return false;
        if (typeof article.title !== "string") return false;
        // Reject non-http(s) URLs at the data layer so they never reach the DOM.
        return isSafeUrl(article.link);

    }

    /**
     * Returns a new article object with all string fields truncated and products
     * filtered to known IDs.  Does not mutate the original.
     */
    function sanitiseArticle(article) {
        return {
            link: article.link, // already validated as safe URL
            title: truncate(article.title, MAX_TITLE_LENGTH),
            summary: truncate(article.summary || "", MAX_SUMMARY_LENGTH),
            source: truncate(article.source || "", 200),
            source_group: truncate(article.source_group || "", 200),
            source_category: truncate(article.source_category || "", 200),
            author: truncate(article.author || "", 200),
            vendor: truncate(article.vendor || "", 200),
            published: article.published || "",
            // Filter products to known IDs so rogue product IDs can't be used
            // to inject unexpected values into data-* attributes or inline styles.
            products: (Array.isArray(article.products) ? article.products : [])
                .filter((p) => p && typeof p.id === "string" && KNOWN_PRODUCT_IDS.has(p.id))
                .map((p) => ({
                    id: p.id,
                    name: truncate(p.name || "", 100),
                })),
        };
    }

    function truncate(str, max) {
        if (typeof str !== "string") return "";
        return str.length > max ? str.slice(0, max) : str;
    }

    // ---------------------------------------------------------------------------
    // URL safety
    // ---------------------------------------------------------------------------

    /**
     * Blocks javascript:, data:, vbscript: and any other non-http(s) URI.
     * Returns true only for http: and https: URLs that parse cleanly.
     */
    function isSafeUrl(url) {
        if (typeof url !== "string" || !url.trim()) return false;
        try {
            const parsed = new URL(url);
            return ALLOWED_URL_SCHEMES.has(parsed.protocol);
        } catch {
            return false;
        }
    }

    // ---------------------------------------------------------------------------
    // Header stats
    // ---------------------------------------------------------------------------
    function updateHeaderStats(data) {
        totalCount.textContent = `${articles.length} articles`;

        if (data.lastUpdated) {
            const dt = new Date(data.lastUpdated);
            // Guard against invalid dates from a tampered feed.
            if (!isNaN(dt.getTime())) {
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
    }

    // ---------------------------------------------------------------------------
    // Filtering & sorting
    // ---------------------------------------------------------------------------
    function applyFilters() {
        let result = [...articles];

        if (currentProduct !== "all") {
            result = result.filter((article) =>
                (article.products || []).some((p) => p.id === currentProduct)
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
                    article.source_group?.toLowerCase().includes(q) ||
                    article.vendor?.toLowerCase().includes(q) ||
                    article.source_category?.toLowerCase().includes(q) ||
                    (article.products || []).some((p) =>
                        p.name.toLowerCase().includes(q)
                    )
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
                result.sort((a, b) => (a.source || "").localeCompare(b.source || ""));
                break;
            case "vendor":
                result.sort((a, b) => (a.vendor || "").localeCompare(b.vendor || ""));
                break;
            default:
                result.sort((a, b) => new Date(b.published) - new Date(a.published));
        }

        filteredArticles = result;
        showingCount.textContent = `Showing ${result.length} of ${articles.length} articles`;
        renderArticles();
    }

    // ---------------------------------------------------------------------------
    // Rendering — product filter pills
    // ---------------------------------------------------------------------------
    function renderProductFilters() {
        const counts = {};

        articles.forEach((article) => {
            (article.products || []).forEach((product) => {
                if (!counts[product.id]) {
                    counts[product.id] = {name: product.name, count: 0};
                }
                counts[product.id].count++;
            });
        });

        // Build pills with DOM methods to avoid any innerHTML with dynamic data.
        filterPills.innerHTML = "";

        const allBtn = document.createElement("button");
        allBtn.className = "pill active";
        allBtn.dataset.product = "all";
        allBtn.textContent = "All Categories ";
        const allCount = document.createElement("span");
        allCount.className = "count";
        allCount.textContent = articles.length;
        allBtn.appendChild(allCount);
        filterPills.appendChild(allBtn);

        Object.entries(counts)
            .sort((a, b) => a[1].name.localeCompare(b[1].name))
            .forEach(([id, product]) => {
                // id is already validated against KNOWN_PRODUCT_IDS by sanitiseArticle.
                const btn = document.createElement("button");
                btn.className = "pill";
                btn.dataset.product = id;
                btn.textContent = product.name + " ";
                const countSpan = document.createElement("span");
                countSpan.className = "count";
                countSpan.textContent = product.count;
                btn.appendChild(countSpan);
                filterPills.appendChild(btn);
            });
    }

    // ---------------------------------------------------------------------------
    // Rendering — article cards
    // ---------------------------------------------------------------------------
    function renderArticles() {
        if (isLoading) return;

        articlesGrid.innerHTML = "";

        if (!filteredArticles.length) {
            showNoResults(true);
            return;
        }

        showNoResults(false);

        // Build every card with DOM methods — zero innerHTML with dynamic content.
        const fragment = document.createDocumentFragment();
        filteredArticles.forEach((article) => {
            fragment.appendChild(buildCard(article));
        });
        articlesGrid.appendChild(fragment);
    }

    function buildCard(article) {
        const isBookmarked = bookmarks.has(article.link);
        const date = new Date(article.published);
        const dateStr = isNaN(date.getTime())
            ? "Unknown date"
            : date.toLocaleDateString("en-GB");

        // --- card root ---
        const card = document.createElement("article");
        card.className = "article-card";

        // --- header row ---
        const cardHeader = document.createElement("div");
        cardHeader.className = "card-header";

        // product tags
        const tagsWrapper = document.createElement("div");
        tagsWrapper.style.cssText = "display:flex;gap:0.5rem;flex-wrap:wrap;";

        (article.products || []).forEach((product) => {
            // Colour is looked up from a static map by a validated key — never
            // interpolated from raw feed data — so there's no CSS injection risk.
            const color = productColors[product.id] || "#64748B";
            const tag = document.createElement("span");
            tag.className = "blog-tag";
            tag.style.background = `${color}22`;
            tag.style.color = color;
            tag.style.border = `1px solid ${color}44`;
            tag.textContent = product.name;
            tagsWrapper.appendChild(tag);
        });

        // bookmark button
        const bookmarkBtn = document.createElement("button");
        bookmarkBtn.className = `bookmark-btn${isBookmarked ? " bookmarked" : ""}`;
        bookmarkBtn.dataset.action = "bookmark";
        // Store the link as a data attribute without encode/decode gymnastics.
        // The link is already validated as a safe http(s) URL, so it's safe to
        // store directly.  We read it back via dataset.link — no decodeURIComponent
        // needed, which eliminates the double-decode risk.
        bookmarkBtn.dataset.link = article.link;
        bookmarkBtn.setAttribute("aria-label", "Toggle bookmark");
        bookmarkBtn.textContent = isBookmarked ? "⭐" : "☆";

        cardHeader.append(tagsWrapper, bookmarkBtn);

        // --- title ---
        const h3 = document.createElement("h3");
        h3.className = "article-title";
        const titleLink = document.createElement("a");
        // link is already validated as http(s) by isValidArticle/isSafeUrl,
        // so assigning to .href is safe and avoids innerHTML URL injection.
        titleLink.href = article.link;
        titleLink.target = "_blank";
        titleLink.rel = "noopener noreferrer"; // added noreferrer
        titleLink.textContent = article.title;
        h3.appendChild(titleLink);

        // --- meta ---
        const meta = document.createElement("div");
        meta.className = "article-meta";
        [
            `🏢 ${article.vendor || "Security"}`,
            `📰 ${article.source}`,
            `🏷️ ${article.source_group}`,
            `📅 ${dateStr}`,
        ].forEach((text) => {
            const span = document.createElement("span");
            span.textContent = text;
            meta.appendChild(span);
        });

        // --- summary ---
        const summary = document.createElement("p");
        summary.className = "article-summary";
        summary.textContent = article.summary;

        card.append(cardHeader, h3, meta, summary);
        return card;
    }

    // ---------------------------------------------------------------------------
    // Bookmarks
    // ---------------------------------------------------------------------------

    /**
     * Load bookmarks defensively — validate that the stored value is an
     * array of strings, reject anything else, and never throw to the caller.
     */
    function loadBookmarks() {
        try {
            const raw = JSON.parse(
                localStorage.getItem("securitynews-bookmarks") || "[]"
            );
            if (!Array.isArray(raw)) return [];
            // Only keep strings that are safe http(s) URLs.
            return raw.filter((item) => typeof item === "string" && isSafeUrl(item));
        } catch {
            return [];
        }
    }

    function persistBookmarks() {
        try {
            localStorage.setItem(
                "securitynews-bookmarks",
                JSON.stringify([...bookmarks])
            );
        } catch (err) {
            // localStorage can throw if storage quota is exceeded.
            console.warn("Could not persist bookmarks:", err);
        }
    }

    function toggleBookmark(link) {
        // Re-validate the URL before acting on it — belt-and-braces in case
        // something slips through the data pipeline.
        if (!isSafeUrl(link)) {
            console.warn("Refused to bookmark unsafe URL:", link);
            return;
        }

        if (bookmarks.has(link)) {
            bookmarks.delete(link);
            showToast("Bookmark removed");
        } else {
            bookmarks.add(link);
            showToast("⭐ Bookmarked");
        }

        persistBookmarks();
        applyFilters();
    }

    // ---------------------------------------------------------------------------
    // Toast
    // ---------------------------------------------------------------------------
    let toastTimer = null;

    function showToast(message) {
        // Use textContent, not innerHTML, to set toast message.
        toastEl.textContent = message;
        toastEl.classList.add("visible");

        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
            toastEl.classList.remove("visible");
            toastTimer = null;
        }, 2500);
    }

    // ---------------------------------------------------------------------------
    // Event listeners
    // ---------------------------------------------------------------------------
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
            bookmarksToggle.setAttribute("aria-pressed", String(showBookmarksOnly));
            applyFilters();
        });

        filterPills.addEventListener("click", (e) => {
            const pill = e.target.closest("[data-product]");
            if (!pill) return;

            // Validate the product value against the known list before
            // assigning it to state — prevents spoofed data-product attributes
            // (e.g. from a browser extension) from polluting the filter state.
            const productVal = pill.dataset.product;
            if (productVal !== "all" && !KNOWN_PRODUCT_IDS.has(productVal)) return;

            filterPills.querySelectorAll(".pill").forEach((p) => {
                p.classList.remove("active");
            });
            pill.classList.add("active");
            currentProduct = productVal;
            applyFilters();
        });

        articlesGrid.addEventListener("click", (e) => {
            const btn = e.target.closest("[data-action]");
            if (!btn) return;

            if (btn.dataset.action === "bookmark") {
                // Read link directly from dataset — no decodeURIComponent needed.
                toggleBookmark(btn.dataset.link);
            }
        });
    }

    // ---------------------------------------------------------------------------
    // Boot
    // ---------------------------------------------------------------------------
    document.addEventListener("DOMContentLoaded", init);
})();