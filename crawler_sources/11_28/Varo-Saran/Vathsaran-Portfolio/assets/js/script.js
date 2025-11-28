// ==========================================================================
// Global Variables and Configuration
// ==========================================================================

const pages = ['index.html', 'about.html', 'skills.html', 'projects.html', 'contact.html'];

// ==========================================================================
// Search Functionality
// ==========================================================================

/**
 * Displays search suggestions and results based on user input
 * @param {string} searchTerm - The term to search for
 */
async function showSuggestionsAndResults(searchTerm) {
    const searchSuggestions = document.querySelector('.search-suggestions');
    const allTerms = [
        'about', 'skills', 'projects', 'contact', 'portfolio', 'data analytics', 'graphic design',
        'vathsaran', 'yasotharan', 'leave management', 'colonist management', 'vortixa website',
        'data visualization', 'e-commerce analytics', 'brand identity', 'adobe photoshop',
        'adobe illustrator', 'adobe indesign', 'adobe premiere pro', 'adobe after effects',
        'adobe animate', 'c#', 'python', 'sql', 'html', 'css', 'javascript', 'statistical analysis',
        'machine learning', 'project management', 'user interface design', 'logo design'
    ];
    
    const suggestions = allTerms.filter(term => term.toLowerCase().includes(searchTerm.toLowerCase()));
    let content = '';

    if (suggestions.length > 0 && searchTerm.length > 0) {
        content += suggestions.map(s => `<li class="suggestion">${s}</li>`).join('');
    }

    if (searchTerm.length > 0) {
        const results = await performSearch(searchTerm);
        if (results.length > 0) {
            content += '<li class="search-results-header">Search Results:</li>';
            content += results.map(result => `
                <li class="search-result">
                    <a href="${result.page}#${result.anchor}">${result.title}</a>
                    <p>${result.snippet}</p>
                </li>
            `).join('');
        } else {
            content += '<li class="no-results">No results found.</li>';
        }
    }

    if (content) {
        searchSuggestions.innerHTML = content;
        searchSuggestions.style.display = 'block';
    } else {
        searchSuggestions.style.display = 'none';
    }
}

/**
 * Performs a search across all pages
 * @param {string} searchTerm - The term to search for
 * @returns {Promise<Array>} Array of search results
 */
async function performSearch(searchTerm) {
    console.log('Performing search for:', searchTerm);
    const results = [];

    for (const page of pages) {
        try {
            const response = await fetch(page);
            const html = await response.text();
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            
            const mainContent = doc.querySelector('main') || doc.querySelector('[role="main"]');
            if (mainContent) {
                const sections = mainContent.querySelectorAll('.section');
                sections.forEach((section, index) => {
                    const sectionTitle = section.querySelector('h2, h3');
                    const sectionContent = section.textContent;
                    if (sectionContent.toLowerCase().includes(searchTerm.toLowerCase())) {
                        const title = sectionTitle ? sectionTitle.textContent : 'Section';
                        const snippet = getSnippet(sectionContent, searchTerm);
                        const anchor = sectionTitle ? sectionTitle.id || `section-${index}` : `section-${index}`;
                        results.push({ page, title, snippet, anchor });
                    }
                });

                const projectCards = mainContent.querySelectorAll('.project-card');
                projectCards.forEach((card, index) => {
                    const cardTitle = card.querySelector('h3');
                    const cardContent = card.textContent;
                    if (cardContent.toLowerCase().includes(searchTerm.toLowerCase())) {
                        const title = cardTitle ? cardTitle.textContent : 'Project';
                        const snippet = getSnippet(cardContent, searchTerm);
                        const anchor = card.id || `project-${index}`;
                        results.push({ page, title, snippet, anchor });
                    }
                });

                const skillItems = mainContent.querySelectorAll('.skill-item');
                skillItems.forEach((item, index) => {
                    const skillName = item.querySelector('h4');
                    if (skillName && skillName.textContent.toLowerCase().includes(searchTerm.toLowerCase())) {
                        const title = skillName.textContent;
                        const snippet = `Skill: ${title}`;
                        const anchor = item.id || `skill-${index}`;
                        results.push({ page, title, snippet, anchor });
                    }
                });
            }
        } catch (error) {
            console.error(`Error searching ${page}:`, error);
        }
    }

    return results;
}

/**
 * Extracts a snippet of text containing the search term
 * @param {string} text - Full text to search within
 * @param {string} searchTerm - Term to find
 * @param {number} snippetLength - Length of snippet (default 150)
 * @returns {string} Formatted snippet with highlighted term
 */
function getSnippet(text, searchTerm, snippetLength = 150) {
    const lowerText = text.toLowerCase();
    const lowerSearchTerm = searchTerm.toLowerCase();
    const index = lowerText.indexOf(lowerSearchTerm);
    if (index === -1) return '';
    
    let start = Math.max(0, index - snippetLength / 2);
    let end = Math.min(text.length, index + searchTerm.length + snippetLength / 2);

    while (start > 0 && text[start] !== ' ') start--;
    while (end < text.length && text[end] !== ' ') end++;

    let snippet = text.slice(start, end).trim();
    if (start > 0) snippet = '...' + snippet;
    if (end < text.length) snippet += '...';

    return snippet.replace(new RegExp(searchTerm, 'gi'), match => `<mark>${match}</mark>`);
}

// ==========================================================================
// Theme Management
// ==========================================================================

/**
 * Initializes the theme toggle functionality
 */
function initThemeToggle() {
    const navWrapper = document.querySelector('.nav-wrapper');
    let themeToggle = navWrapper ? navWrapper.querySelector('.theme-toggle') : null;

    if (!themeToggle) {
        themeToggle = document.createElement('button');
        themeToggle.id = 'themeToggle';
        themeToggle.className = 'theme-toggle';
        themeToggle.setAttribute('aria-label', 'Toggle Dark/Light Mode');
        themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        
        if (navWrapper) {
            navWrapper.appendChild(themeToggle);
        } else {
            console.error('Nav wrapper not found, falling back to body');
            document.body.appendChild(themeToggle);
        }
    } else {
        themeToggle.id = 'themeToggle';
    }

    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
        themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
    } else if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
        document.documentElement.setAttribute('data-theme', 'dark');
        themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
    }

    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.classList.add('theme-transition');
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);

        themeToggle.innerHTML = newTheme === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
        themeToggle.classList.add('rotate-animation');

        setTimeout(() => {
            themeToggle.classList.remove('rotate-animation');
            document.documentElement.classList.remove('theme-transition');
        }, 500);
    }

    themeToggle.addEventListener('click', toggleTheme);
}

// ==========================================================================
// Particle Background Management
// ==========================================================================

/**
 * Updates particle configuration based on current theme
 */
function updateParticlesForTheme() {
    if (typeof particlesJS === 'undefined') return;

    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const baseConfig = {
        particles: {
            number: { value: 120, density: { enable: true, value_area: 800 } },
            shape: { type: ["circle", "triangle", "edge"], stroke: { width: 0, color: "#000000" } },
            opacity: { value: 0.6, random: true, anim: { enable: true, speed: 1, opacity_min: 0.1, sync: false } },
            size: { value: 3, random: true, anim: { enable: true, speed: 2, size_min: 0.1, sync: false } },
            move: { 
                enable: true, speed: 3, direction: "none", random: true, straight: false, 
                out_mode: "out", bounce: false, attract: { enable: true, rotateX: 600, rotateY: 1200 } 
            }
        },
        interactivity: {
            detect_on: "canvas",
            events: { onhover: { enable: true, mode: "grab" }, onclick: { enable: true, mode: "push" }, resize: true },
            modes: { 
                grab: { distance: 200, line_linked: { opacity: 1 } },
                bubble: { distance: 400, size: 40, duration: 2, opacity: 8, speed: 3 },
                repulse: { distance: 200, duration: 0.4 },
                push: { particles_nb: 4 },
                remove: { particles_nb: 2 }
            }
        },
        retina_detect: true
    };

    const themeConfigs = {
        dark: {
            particles: {
                color: { value: ["#00bfff", "#1e90ff", "#4dc3ff"] },
                line_linked: { enable: true, distance: 150, color: "#00bfff", opacity: 0.4, width: 1, shadow: { enable: true, color: "#00bfff", blur: 5 } }
            }
        },
        light: {
            particles: {
                color: { value: ["#42A5F5", "#2196F3", "#1976D2"] },
                line_linked: { enable: true, distance: 150, color: "#2196F3", opacity: 0.4, width: 1, shadow: { enable: true, color: "#2196F3", blur: 3 } }
            }
        }
    };

    function deepMerge(target, source) {
        for (const key in source) {
            if (source.hasOwnProperty(key)) {
                if (typeof source[key] === 'object' && source[key] !== null && target[key]) {
                    deepMerge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
        }
        return target;
    }

    const finalConfig = deepMerge(JSON.parse(JSON.stringify(baseConfig)), themeConfigs[currentTheme]);
    particlesJS('particles-js', finalConfig);

    document.getElementById('particles-js').style.opacity = currentTheme === 'light' ? '0.65' : '1';
}

/**
 * Backward compatibility for particle initialization
 */
function initParticles() {
    console.log("Using updated particles system");
    updateParticlesForTheme();
}

/**
 * Sets up listeners for theme changes affecting particles
 */
function setupThemeChangeListeners() {
    const themeToggles = document.querySelectorAll('#themeToggle, #mobileThemeToggle');
    themeToggles.forEach(toggle => {
        toggle.addEventListener('click', () => {
            setTimeout(updateParticlesForTheme, 100);
        });
    });
    setTimeout(updateParticlesForTheme, 500);
}

// ==========================================================================
// Utility Functions
// ==========================================================================

/**
 * Executes a function when DOM is ready
 * @param {Function} fn - Function to execute
 */
function domReady(fn) {
    if (document.readyState === "complete" || document.readyState === "interactive") {
        setTimeout(fn, 1);
    } else {
        document.addEventListener("DOMContentLoaded", fn);
    }
}

/**
 * Debounces a function for performance optimization
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in ms
 * @param {boolean} immediate - Whether to call immediately
 * @returns {Function} Debounced function
 */
function debounce(func, wait = 20, immediate = true) {
    let timeout;
    return function() {
        const context = this, args = arguments;
        const later = function() {
            timeout = null;
            if (!immediate) func.apply(context, args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func.apply(context, args);
    };
}

// ==========================================================================
// Slider Functionality
// ==========================================================================

/**
 * Initializes the hero slider with typing effect
 */
function initSlider() {
    const slider = document.querySelector('.hero-slider');
    const slides = document.querySelectorAll('.slide');
    const prevBtn = document.querySelector('.slider-prev');
    const nextBtn = document.querySelector('.slider-next');
    const dotsContainer = document.querySelector('.slider-dots');
    let currentSlide = 0;
    let slideInterval;

    function createDots() {
        slides.forEach((_, index) => {
            const dot = document.createElement('span');
            dot.classList.add('slider-dot');
            dot.addEventListener('click', () => goToSlide(index));
            dotsContainer.appendChild(dot);
        });
    }

    function updateDots() {
        document.querySelectorAll('.slider-dot').forEach((dot, index) => {
            dot.classList.toggle('active', index === currentSlide);
        });
    }

    function showSlide(index) {
        const slideCount = slides.length;
        const newPosition = -index * 100;

        if (index >= slideCount) {
            slider.style.transition = 'none';
            slider.style.transform = `translateX(0%)`;
            slider.offsetHeight;
            slider.style.transition = 'transform 0.5s ease-in-out';
            slider.style.transform = `translateX(0%)`;
            currentSlide = 0;
        } else if (index < 0) {
            slider.style.transition = 'none';
            slider.style.transform = `translateX(-${(slideCount - 1) * 100}%)`;
            slider.offsetHeight;
            slider.style.transition = 'transform 0.5s ease-in-out';
            slider.style.transform = `translateX(-${(slideCount - 1) * 100}%)`;
            currentSlide = slideCount - 1;
        } else {
            slider.style.transition = 'transform 0.5s ease-in-out';
            slider.style.transform = `translateX(${newPosition}%)`;
            currentSlide = index;
        }

        slides.forEach((slide, i) => {
            slide.classList.toggle('active', i === currentSlide);
        });
        updateDots();
        typeTexts(slides[currentSlide]);
    }

    function nextSlide() {
        showSlide(currentSlide + 1);
    }

    function prevSlide() {
        showSlide(currentSlide - 1);
    }

    function goToSlide(index) {
        showSlide(index);
        resetInterval();
    }

    function resetInterval() {
        clearInterval(slideInterval);
        slideInterval = setInterval(nextSlide, 7000);
    }

    function typeTexts(slide) {
        const heading = slide.querySelector('h2');
        const paragraph = slide.querySelector('p');

        if (heading) {
            if (paragraph) {
                paragraph.style.opacity = '0';
                paragraph.style.visibility = 'hidden';
            }
            typeText(heading, () => {
                if (paragraph) {
                    paragraph.style.visibility = 'visible';
                    paragraph.style.opacity = '1';
                    paragraph.textContent = '';
                    setTimeout(() => typeText(paragraph), 500);
                }
            });
        } else if (paragraph) {
            typeText(paragraph);
        }
    }

    function typeText(element, callback) {
        if (!element) return;
        const text = element.getAttribute('data-text');
        element.textContent = '';
        element.classList.add('typing-text');
        let i = 0;
        const typingInterval = setInterval(() => {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
            } else {
                clearInterval(typingInterval);
                element.classList.remove('typing-text');
                if (callback) callback();
            }
        }, 70);
    }

    createDots();
    showSlide(0);
    resetInterval();

    prevBtn.addEventListener('click', () => {
        prevSlide();
        resetInterval();
    });

    nextBtn.addEventListener('click', () => {
        nextSlide();
        resetInterval();
    });
}

// ==========================================================================
// Project Filtering
// ==========================================================================

/**
 * Initializes project filtering functionality
 */
function initProjectFilter() {
    if (!document.querySelector('.project-grid')) return;

    const filterContainer = document.createElement('div');
    filterContainer.className = 'filter-container fade-in-up';

    const filterTitle = document.createElement('h3');
    filterTitle.textContent = 'Filter Projects by Skills';
    filterTitle.className = 'filter-title';
    filterContainer.appendChild(filterTitle);

    const skillsSet = new Set();
    const projectCards = document.querySelectorAll('.project-card');

    projectCards.forEach(card => {
        const techTags = card.querySelectorAll('.tech-tag');
        techTags.forEach(tag => skillsSet.add(tag.textContent.trim()));
    });

    const skillsContainer = document.createElement('div');
    skillsContainer.className = 'skills-filter-buttons';

    const allButton = document.createElement('button');
    allButton.textContent = 'All';
    allButton.className = 'filter-btn active';
    allButton.setAttribute('data-skill', 'all');
    skillsContainer.appendChild(allButton);

    skillsSet.forEach(skill => {
        const skillButton = document.createElement('button');
        skillButton.textContent = skill;
        skillButton.className = 'filter-btn';
        skillButton.setAttribute('data-skill', skill);
        skillsContainer.appendChild(skillButton);
    });

    filterContainer.appendChild(skillsContainer);
    const projectSection = document.querySelector('.project-grid').parentElement;
    projectSection.insertBefore(filterContainer, document.querySelector('.project-grid'));

    const filterButtons = document.querySelectorAll('.filter-btn');

    filterButtons.forEach(button => {
        button.addEventListener('click', () => {
            filterButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            const skill = button.getAttribute('data-skill');

            projectCards.forEach(card => {
                if (skill === 'all') {
                    card.style.display = 'flex';
                    card.classList.add('fade-in-up');
                    return;
                }

                const techTags = Array.from(card.querySelectorAll('.tech-tag'))
                    .map(tag => tag.textContent.trim());

                card.style.display = techTags.includes(skill) ? 'flex' : 'none';
                if (techTags.includes(skill)) card.classList.add('fade-in-up');
            });
        });
    });
}

// ==========================================================================
// Scroll Animation
// ==========================================================================

/**
 * Checks if an element is in viewport
 * @param {Element} el - Element to check
 * @returns {boolean} Whether element is visible
 */
function isElementInViewport(el) {
    const rect = el.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

/**
 * Handles scroll animations for fade-in elements
 */
function handleScrollAnimation() {
    const elements = document.querySelectorAll('.fade-in-up');
    elements.forEach(element => {
        if (isElementInViewport(element)) {
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }
    });
}

// ==========================================================================
// Mobile Menu
// ==========================================================================

/**
 * Initializes mobile menu functionality
 */
function initMobileMenu() {
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    const navLinks = document.querySelector('.nav-links');

    let mobileMenuOverlay = document.getElementById('mobileMenuOverlay');
    if (!mobileMenuOverlay) {
        mobileMenuOverlay = document.createElement('div');
        mobileMenuOverlay.id = 'mobileMenuOverlay';
        mobileMenuOverlay.className = 'mobile-menu-overlay';
        document.body.appendChild(mobileMenuOverlay);

        const closeButton = document.createElement('button');
        closeButton.className = 'mobile-menu-close';
        closeButton.innerHTML = '<i class="fas fa-times"></i>';
        closeButton.setAttribute('aria-label', 'Close menu');
        mobileMenuOverlay.appendChild(closeButton);

        const mobileThemeToggle = document.createElement('div');
        mobileThemeToggle.className = 'mobile-theme-toggle-container';
        mobileThemeToggle.innerHTML = `
            <span>Theme</span>
            <button id="mobileThemeToggle" class="mobile-theme-toggle" aria-label="Toggle Dark/Light Mode">
                <i class="fas fa-moon"></i>
            </button>
        `;
        mobileMenuOverlay.appendChild(mobileThemeToggle);

        const mobileNavLinks = navLinks.cloneNode(true);
        mobileNavLinks.className = 'mobile-nav-links';
        mobileMenuOverlay.appendChild(mobileNavLinks);

        const mobileTToggle = document.getElementById('mobileThemeToggle');
        setupThemeToggle(mobileTToggle);

        closeButton.addEventListener('click', () => {
            mobileMenuToggle.classList.remove('active');
            mobileMenuOverlay.classList.remove('active');
            document.body.classList.remove('menu-open');
            mobileMenuOverlay.style.animation = 'fadeOutRight 0.3s forwards';
            setTimeout(() => {
                mobileMenuOverlay.style.display = 'none';
                mobileMenuOverlay.style.animation = '';
            }, 300);
        });

        const mobileNavLinkItems = mobileMenuOverlay.querySelectorAll('.mobile-nav-links a');
        mobileNavLinkItems.forEach(link => {
            link.addEventListener('click', () => closeButton.click());
        });
    }

    mobileMenuToggle.addEventListener('click', () => {
        mobileMenuToggle.classList.toggle('active');
        mobileMenuOverlay.style.display = 'block';
        
        setTimeout(() => {
            mobileMenuOverlay.classList.toggle('active');
            document.body.classList.toggle('menu-open');
            
            mobileMenuOverlay.style.animation = mobileMenuOverlay.classList.contains('active') 
                ? 'fadeInRight 0.3s forwards' 
                : 'fadeOutRight 0.3s forwards';
            
            if (!mobileMenuOverlay.classList.contains('active')) {
                setTimeout(() => {
                    mobileMenuOverlay.style.display = 'none';
                    mobileMenuOverlay.style.animation = '';
                }, 300);
            }
        }, 10);
    });

    document.addEventListener('click', (event) => {
        const isClickInsideNav = navLinks.contains(event.target);
        const isClickOnToggle = mobileMenuToggle.contains(event.target);
        const isClickInOverlay = mobileMenuOverlay && mobileMenuOverlay.contains(event.target);

        if (!isClickInsideNav && !isClickOnToggle && !isClickInOverlay && mobileMenuOverlay.classList.contains('active')) {
            mobileMenuToggle.click();
        }
    });
}

/**
 * Sets up theme toggle for a specific button
 * @param {Element} toggleButton - Button to setup
 */
function setupThemeToggle(toggleButton) {
    if (!toggleButton) return;

    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    toggleButton.innerHTML = currentTheme === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';

    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.classList.add('theme-transition');
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);

        const allToggles = document.querySelectorAll('#themeToggle, #mobileThemeToggle');
        allToggles.forEach(toggle => {
            toggle.innerHTML = newTheme === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
            toggle.classList.add('rotate-animation');
        });

        setTimeout(() => {
            allToggles.forEach(toggle => toggle.classList.remove('rotate-animation'));
            document.documentElement.classList.remove('theme-transition');
        }, 500);
    }

    toggleButton.addEventListener('click', toggleTheme);
}

/**
 * Applies theme from storage or system preference
 */
function applyTheme() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
    } else if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
}

// ==========================================================================
// DOM Ready Event Listeners
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    const navLinks = document.querySelector('.nav-links');
    const searchInput = document.querySelector('.search-input');
    const searchBtn = document.querySelector('.search-btn');
    const searchSuggestions = document.querySelector('.search-suggestions');

    initMobileMenu();
    initThemeToggle();
    initParticles();
    if (document.querySelector('.hero-slider')) initSlider();
    initProjectFilter();

    if (searchInput && searchBtn) {
        let debounceTimer;

        searchInput.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => showSuggestionsAndResults(searchInput.value), 300);
        });

        searchBtn.addEventListener('click', (e) => {
            e.preventDefault();
            showSuggestionsAndResults(searchInput.value);
        });

        document.addEventListener('click', (e) => {
            if (!searchInput.contains(e.target) && !searchSuggestions.contains(e.target)) {
                searchSuggestions.style.display = 'none';
            }
        });

        searchSuggestions.addEventListener('click', (e) => {
            const suggestionItem = e.target.closest('.suggestion');
            const searchResultItem = e.target.closest('.search-result');

            if (suggestionItem) {
                const selectedText = suggestionItem.textContent;
                searchInput.value = selectedText;
                showSuggestionsAndResults(selectedText);
            } else if (searchResultItem) {
                const link = searchResultItem.querySelector('a');
                if (link) {
                    e.preventDefault();
                    const href = link.getAttribute('href');
                    const [page, anchor] = href.split('#');

                    if (page === window.location.pathname.split('/').pop()) {
                        const targetElement = document.getElementById(anchor);
                        if (targetElement) targetElement.scrollIntoView({ behavior: 'smooth' });
                    } else {
                        window.location.href = href;
                    }
                }
            }
            searchSuggestions.style.display = 'none';
        });

        searchInput.addEventListener('focus', () => {
            searchInput.style.boxShadow = `0 0 10px var(--accent-color)`;
        });

        searchInput.addEventListener('blur', () => {
            searchInput.style.boxShadow = 'none';
        });

        console.log('Search event listeners attached');
    } else {
        console.error('Search input or button not found');
    }

    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            if (!validateForm(this)) return;

            const submitButton = this.querySelector('.submit-btn');
            let feedbackDiv = document.querySelector('.form-feedback');
            if (!feedbackDiv) {
                feedbackDiv = document.createElement('div');
                feedbackDiv.className = 'form-feedback';
                this.appendChild(feedbackDiv);
            }

            try {
                submitButton.disabled = true;
                submitButton.textContent = 'Sending...';
                feedbackDiv.textContent = 'Submitting your message...';
                feedbackDiv.className = 'form-feedback info';

                const formData = new FormData(this);
                const response = await fetch(this.action, {
                    method: 'POST',
                    body: formData,
                    headers: { 'Accept': 'application/json' }
                });

                const result = await response.json();

                if (response.ok) {
                    feedbackDiv.textContent = 'Thank you for your message. I will get back to you soon!';
                    feedbackDiv.className = 'form-feedback success';
                    this.reset();
                } else {
                    throw new Error(result.error || 'Form submission failed');
                }
            } catch (error) {
                console.error('Error submitting form:', error);
                feedbackDiv.textContent = 'There was an error submitting your message. Please try again later.';
                feedbackDiv.className = 'form-feedback error';
            } finally {
                submitButton.disabled = false;
                submitButton.textContent = 'Send Message';
                feedbackDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        });
    }

    const scrollToTopBtn = document.getElementById("scrollToTopBtn");
    window.onscroll = function() {
        if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
            scrollToTopBtn.style.display = "block";
        } else {
            scrollToTopBtn.style.display = "none";
        }
    };

    scrollToTopBtn.addEventListener("click", () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    handleScrollAnimation();
    applyTheme();
});

window.addEventListener('scroll', debounce(handleScrollAnimation));

// ==========================================================================
// Form Validation
// ==========================================================================

/**
 * Validates form fields
 * @param {HTMLFormElement} form - Form to validate
 * @returns {boolean} Whether form is valid
 */
function validateForm(form) {
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;

    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            isValid = false;
            field.classList.add('error');
            let errorMsg = field.nextElementSibling;
            if (!errorMsg || !errorMsg.classList.contains('error-message')) {
                errorMsg = document.createElement('span');
                errorMsg.className = 'error-message';
                field.parentNode.insertBefore(errorMsg, field.nextSibling);
            }
            errorMsg.textContent = `${field.name} is required`;
        } else {
            field.classList.remove('error');
            const errorMsg = field.nextElementSibling;
            if (errorMsg && errorMsg.classList.contains('error-message')) errorMsg.remove();
        }
    });

    return isValid;
}

// ==========================================================================
// Chatbot Functionality
// ==========================================================================

const knowledgeBase = [
  // Greeting responses
  {
    keywords: ['hello', 'hi', 'hey', 'greetings'],
    response: "Good day! I'm iXiA mini, Vathsaran's digital assistant. How may I help you explore his data analytics and design expertise today?"
    // General greeting introducing the assistant, fits in knowledgeBase
  },
  {
    keywords: ['how are you', "how's it going", "what's up"],
    response: "I'm functioning optimally! I'd be happy to tell you about Vathsaran's projects, skills in data analytics, or help you navigate his portfolio. What are you most interested in learning about?"
    // General inquiry about well-being, conversational, belongs in knowledgeBase
  },

  // Design Specific Responses
  {
    keywords: ['design', 'graphic design', 'visual design'],
    response: "Vathsaran has substantial experience in graphic design with a Diploma from AMDT College. His design approach emphasizes clean aesthetics and meaningful communication. This background uniquely enhances his data visualization work, allowing him to present complex information with visual clarity and impact. Would you like to see examples of his design work?"
    // Focuses on graphic design skills, not specifically data analytics, so it’s in knowledgeBase
  },
  {
    keywords: ['adobe', 'creative suite', 'photoshop', 'illustrator'],
    response: "Vathsaran is highly proficient in Adobe Creative Suite. His skills include Photoshop (80%), Illustrator (95%), InDesign (60%), Premiere Pro (50%), After Effects (40%), and Animate (60%). This expertise allows him to create professional graphics, layouts, and visual assets for both design projects and data visualization work."
    // Details Adobe design tools, primarily design-focused, fits in knowledgeBase
  },
  {
    keywords: ['ui', 'ux', 'user interface', 'user experience'],
    response: "Vathsaran applies user interface design principles in both his web development and data visualization work. He focuses on creating intuitive, accessible interfaces that enhance user engagement with information. His approach balances aesthetic appeal with functional clarity, ensuring that interfaces serve both information and experience goals."
    // General UI/UX design principles, not exclusively data analytics, so it’s in knowledgeBase
  },
  {
    keywords: ['brand', 'branding', 'identity'],
    response: "Vathsaran has created comprehensive brand identities for various clients, developing cohesive visual systems including logos, color palettes, typography, and brand guidelines. His Brand Identity Design projects demonstrate his ability to translate brand values and positioning into compelling visual expressions."
    // Focuses on branding and design, not data analytics, belongs in knowledgeBase
  },

  // Project Specific Responses (Non-Data Analytics)
  {
    keywords: ['vortixa', 'website', 'web development'],
    response: "The Vortixa Website project showcases Vathsaran's web development skills. Using HTML5, CSS3, and JavaScript, he created a responsive, modern website for this IT services company. The site features smooth animations, mobile-friendly design, and optimized performance. The project demonstrates his ability to blend technical implementation with compelling visual design."
    // Web development and design project, not primarily data analytics, fits in knowledgeBase
  },

  // Education and Background Responses
  {
    keywords: ['education', 'study', 'degree', 'qualifications'],
    response: "Vathsaran is currently pursuing a Higher National Diploma in Data Analytics at Esoft Metro Campus (2024-Present). His educational background includes a Diploma in Information Technology from ICBT Campus (2017) and a Diploma in Graphic Design from AMDT College (2019). This multidisciplinary education combines technical and creative foundations, positioning him uniquely at the intersection of data and design."
    // General education overview, not specific to data analytics practice, so it’s in knowledgeBase
  },
  {
    keywords: ['experience', 'work history', 'background'],
    response: "Vathsaran's professional journey includes freelance graphic design (2018-2020), diverse creative projects (2021-2023), and design tutoring (2023-2024). He's now focusing on data analytics while leveraging his design expertise. This combination of analytical and creative experience enables him to bridge technical data work with effective visual communication."
    // General career background, covers design and analytics broadly, fits in knowledgeBase
  },
  {
    keywords: ['career goals', 'aspirations', 'future plans'],
    response: "Vathsaran aims to become a leading data analyst who excels in both technical analysis and visual storytelling. His goals include mastering advanced statistical methods and machine learning, creating innovative data visualizations, contributing to data-driven decision-making in creative industries, and eventually leading analytics initiatives. He's committed to continuous learning in this rapidly evolving field."
    // General career aspirations, not specific data analytics details, belongs in knowledgeBase
  },

  // Contact and Collaboration Responses
  {
    keywords: ['contact', 'reach', 'get in touch', 'hire'],
    response: "You can reach Vathsaran via email at varosaran@gmail.com, by phone at +94777275526, through LinkedIn (Vathsaran Yasotharan), or via GitHub (github.com/Varo-Saran). The Contact page also includes a form to send messages directly. He's open to discussing freelance projects, collaboration opportunities, and permanent positions."
    // Contact information, general and not data-specific, fits in knowledgeBase
  },
  {
    keywords: ['freelance', 'hire', 'collaboration', 'work with'],
    response: "Vathsaran is available for freelance projects and collaborations in data analytics, data visualization, and graphic design. His multidisciplinary skill set makes him ideal for projects requiring both analytical rigor and visual communication. For inquiries about rates, availability, or specific project needs, please use the contact form or email directly at varosaran@gmail.com."
    // General collaboration info, covers both design and analytics broadly, so it’s in knowledgeBase
  },
  {
    keywords: ['portfolio', 'website', 'site'],
    response: "You're currently exploring Vathsaran's portfolio website, which showcases his data analytics and design capabilities. The site features sections on his skills, projects, background, and contact information. The futuristic, interactive design reflects his aesthetic sensibilities. Is there a particular section you'd like me to help you navigate to?"
    // General portfolio overview, not data analytics-specific, belongs in knowledgeBase
  },

  // Personality and Conversational Responses
  {
    keywords: ['joke', 'funny', 'laugh'],
    response: "Why don't data scientists get invited to parties? Because they're too busy trying to find the correlation between 'chips' and 'dips'! Would you like another data joke?"
    // Conversational humor, general and not technical, fits in knowledgeBase
  },
  {
    keywords: ['who are you', 'what are you', 'about you'],
    response: "I'm Jarvis, Vathsaran's AI assistant. I'm here to help you learn about his skills in data analytics and design, explore his projects, and connect if you're interested in collaboration. Unlike Vathsaran, I can't create stunning visualizations, but I can certainly tell you all about how he does it!"
    // General introduction of the assistant, belongs in knowledgeBase
  },
  {
    keywords: ['thank you', 'thanks'],
    response: "You're welcome! I'm always here to help showcase Vathsaran's data analytics and design expertise. If you have more questions later or want to discuss a potential project, feel free to use the contact form. Wishing you a data-driven day!"
    // General thank-you response, conversational, fits in knowledgeBase
  },
  {
    keywords: ['bye', 'goodbye', 'later'],
    response: "Thank you for exploring Vathsaran's portfolio! If you'd like to see his work in action or discuss potential collaborations, don't hesitate to reach out through the contact form. Have a great day, and may your datasets always be clean and your visualizations insightful!"
    // General farewell, not data-specific, belongs in knowledgeBase
  },

  // Technical Skill Questions
  {
    keywords: ['technical skills', 'tech skills', 'what can you do'],
    response: "Vathsaran's key technical skills include: data analysis with Python (Pandas, NumPy) and SQL, data visualization (Plotly, Tableau), statistical analysis, basic machine learning, Adobe Creative Suite (Photoshop 80%, Illustrator 95%), web development (HTML 90%, CSS 60%, JavaScript 20%), and database management. Would you like more details about any specific skill area?"
    // Broad overview of skills (design and analytics), not specific to data analytics practice, so it’s in knowledgeBase
  },
  {
    keywords: ['languages', 'programming languages', 'coding'],
    response: "Vathsaran is proficient in several programming and markup languages, including Python (50%) for data analysis, SQL (40%) for database queries, C# (30%) for application development, HTML (90%) and CSS (60%) for web development, and JavaScript (20%) for interactive elements. These technical skills complement his analytical and design capabilities."
    // General list of programming languages, covers both areas broadly, fits in knowledgeBase
  },

  // Fallback Responses
  {
    keywords: ['unknown', 'not sure', 'confused'],
    response: "I'm not quite sure I understood your question about Vathsaran's data analytics and design work. Could you rephrase? I'm happy to tell you about his technical skills, projects, visualization expertise, or how to get in touch for collaboration opportunities."
    // General fallback for unclear queries, belongs in knowledgeBase
  },
  {
    keywords: ['default'],
    response: "That's an interesting question! While I don't have specific information about that, I'd be happy to tell you about Vathsaran's data analytics skills, design work, or ongoing projects. Or would you prefer information about contacting him for collaboration opportunities?"
    // General default response, not data-specific, fits in knowledgeBase
  }
];

const dataAnalyticsResponses = [
  // Data Analytics Specific Responses
  {
    keywords: ['data analytics', 'data analysis', 'analytics', 'analyze data'],
    response: "Vathsaran specializes in data analytics, transforming complex datasets into actionable insights. He's proficient in Python, SQL, and statistical analysis. His analytics approach combines technical precision with visual storytelling to make data accessible and impactful. Would you like to see specific data analytics projects he's worked on?"
    // Overview of data analytics expertise, clearly data-specific, fits in dataAnalyticsResponses
  },
  {
    keywords: ['data visualization', 'visualize data', 'charts', 'graphs', 'dashboard'],
    response: "Data visualization is where Vathsaran's analytics and design skills converge. He creates interactive dashboards and visual narratives that make complex data intuitive and compelling. He uses tools like Plotly, Tableau, and custom Python visualizations to transform numbers into visual stories. His E-commerce Analytics Tool project is a great example of this work."
    // Specific to data visualization in analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['python', 'pandas', 'numpy', 'jupyter'],
    response: "Vathsaran uses Python extensively in his data analysis workflow. He's skilled with essential libraries like Pandas for data manipulation, NumPy for numerical analysis, and various visualization libraries. His approach typically involves exploratory data analysis, statistical modeling, and creating reproducible research in Jupyter notebooks. Would you like to see Python-specific projects?"
    // Details Python use in data analytics, fits in dataAnalyticsResponses
  },
  {
    keywords: ['sql', 'database', 'queries'],
    response: "Vathsaran is experienced with SQL for data extraction and analysis. He can write complex queries to aggregate and analyze data from relational databases. He's used SQL in projects like the Leave Management System and E-commerce Analytics Tool, working with both transaction and analytical databases. Need more specific information about his SQL expertise?"
    // SQL use in data analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['machine learning', 'ml', 'algorithms', 'ai'],
    response: "Vathsaran has foundational knowledge in machine learning, focusing on practical applications for business problems. His skills include basic regression, classification, and clustering models. While he's still developing advanced ML expertise as part of his data analytics studies, he approaches these techniques with a critical thinking mindset, focusing on interpretability and business value."
    // Machine learning in data analytics context, fits in dataAnalyticsResponses
  },
  {
    keywords: ['statistical', 'statistics', 'analysis'],
    response: "Statistical analysis is central to Vathsaran's data approach. He's knowledgeable about descriptive statistics, hypothesis testing, correlation analysis, and regression modeling. He ensures statistical soundness in his data projects, balancing technical rigor with clear communication of findings for non-technical stakeholders."
    // Statistical methods in data analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['tableau', 'power bi', 'data tools'],
    response: "Vathsaran is skilled with data visualization platforms like Tableau, which he used in his E-commerce Analytics Tool project. His background in design gives him an edge in creating dashboards that are both insightful and visually appealing. He focuses on creating interactive visualizations that allow stakeholders to explore data and discover insights themselves."
    // Tableau and data visualization tools in analytics, fits in dataAnalyticsResponses
  },

  // Project Specific Responses (Data Analytics)
  {
    keywords: ['leave management', 'leave system'],
    response: "The Leave Management System was developed for Grifindor Toys using C#, SQL, and WinForms. This enterprise application streamlined the leave request workflow, improving efficiency by 40% and employee satisfaction. The system features automated approval routing, leave balance tracking, and analytical reporting for HR management."
    // Includes analytical reporting, data analytics-related, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['colonist', 'colonist management', 'space'],
    response: "The Colonist Management Software, created for E-Space Solutions, is a resource planning system for space colonization simulations. Built with Python, SQLite, and Tkinter, it helps manage personnel schedules, resource allocation, and habitat systems. The software includes predictive modeling for resource consumption and interactive visualization of colony metrics."
    // Features predictive modeling and visualization, data analytics-specific, fits in dataAnalyticsResponses
  },
  {
    keywords: ['visualization dashboard', 'data dashboard'],
    response: "Vathsaran's Data Visualization Dashboard project transformed complex datasets into interactive, user-friendly visualizations. Built with Python, Pandas, and Plotly, this dashboard enables stakeholders to explore data through customizable views and filters. The project demonstrates his ability to make data accessible and actionable through thoughtful visual design and technical implementation."
    // Data visualization project, clearly analytics-focused, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['e-commerce', 'retail', 'sales analytics'],
    response: "The E-commerce Analytics Tool analyzes customer behavior and sales trends for online retailers. Developed using Python, SQL, and Tableau, it provides insights on customer segments, purchase patterns, and product performance. The tool includes predictive features for inventory planning and marketing optimization, demonstrating Vathsaran's ability to deliver business value through data analysis."
    // E-commerce analytics with predictive features, fits in dataAnalyticsResponses
  },

  // Data-specific Conversation Starters
  {
    keywords: ['data project', 'analytics project', 'case study'],
    response: "Vathsaran has worked on several data analytics projects, including: an E-commerce Analytics Tool that increased sales conversion by 15%, a Data Visualization Dashboard that reduced decision-making time by 30%, and predictive models for inventory management. Which type of analytics project are you most interested in hearing about?"
    // Highlights data analytics projects, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['business intelligence', 'bi', 'reporting'],
    response: "Vathsaran approaches Business Intelligence as the bridge between raw data and strategic decision-making. He creates analytical reports and dashboards that translate complex metrics into actionable insights. His work emphasizes self-service BI tools that empower stakeholders to explore data independently while maintaining analytical rigor in the underlying data modeling."
    // Business intelligence and analytics, fits in dataAnalyticsResponses
  },
  {
    keywords: ['data ethics', 'privacy', 'responsible'],
    response: "Vathsaran is committed to ethical data practices, including privacy protection, transparent methodology, and avoiding biased analysis. He believes responsible data use builds trust and creates sustainable value. In his projects, he implements data anonymization, clear documentation of assumptions, and careful consideration of the societal implications of analytical work."
    // Data ethics in analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['big data', 'large datasets', 'data processing'],
    response: "While continuing to develop his big data skills, Vathsaran understands the principles of working with large datasets. He focuses on efficient data processing techniques, appropriate sampling methods, and scalable visualization approaches. He's currently expanding his knowledge of distributed computing tools and cloud-based analytics platforms through his data analytics program."
    // Big data concepts in analytics, fits in dataAnalyticsResponses
  },

  // Data Methodology Responses
  {
    keywords: ['data methodology', 'data process', 'analytics approach'],
    response: "Vathsaran follows a structured data analytics methodology: 1) Problem Definition - clarifying business questions, 2) Data Collection & Cleaning - ensuring quality and relevance, 3) Exploratory Analysis - discovering patterns and relationships, 4) Advanced Analysis - applying statistical methods, 5) Visualization & Communication - translating findings into actionable insights. This systematic approach ensures rigorous analysis with business-relevant outcomes."
    // Detailed analytics methodology, clearly data-specific, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['data cleaning', 'data preparation', 'preprocessing'],
    response: "Vathsaran understands that data cleaning is often 80% of a data project. He's experienced in handling missing values, outlier detection, data normalization, and feature engineering. His approach emphasizes documentation of cleaning steps for reproducibility. He uses Python's Pandas for transformations and maintains data quality through automated validation checks."
    // Data cleaning techniques, analytics-specific, fits in dataAnalyticsResponses
  },
  {
    keywords: ['data sources', 'data collection', 'data gathering'],
    response: "Vathsaran works with diverse data sources including relational databases, CSV files, APIs, and web scraping. He emphasizes proper data collection planning to ensure representativeness and relevance to business questions. For the E-commerce Analytics Tool, he integrated customer transaction data, website behavior logs, and product information to create a comprehensive analytical view."
    // Data collection in analytics, belongs in dataAnalyticsResponses
  },

  // Technical Data Skills
  {
    keywords: ['data tools', 'analytics tools', 'software'],
    response: "Vathsaran's technical toolkit includes: Python with Pandas, NumPy, Matplotlib, and Plotly for analysis and visualization; SQL for database queries; Tableau for interactive dashboards; Excel for quick analysis; Git for version control; and Jupyter Notebooks for reproducible research. He continues expanding his toolset through his data analytics studies, focusing on tools that enable efficient, insightful analysis."
    // Analytics-specific tools, fits in dataAnalyticsResponses
  },
  {
    keywords: ['exploratory data analysis', 'eda', 'data exploration'],
    response: "Exploratory Data Analysis is central to Vathsaran's approach. He starts by understanding variable distributions, identifying patterns and correlations, and generating initial hypotheses. He uses visualization techniques extensively during EDA to reveal insights that might be missed in purely numerical analysis. This exploratory phase informs his subsequent statistical modeling and ensures analysis directions align with the data's natural patterns."
    // EDA in analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['excel', 'spreadsheet', 'spreadsheet analysis'],
    response: "While Vathsaran focuses on programmatic analysis with Python and SQL for scalability, he's also proficient with Excel for quick analyses and stakeholder-friendly outputs. He's skilled with pivot tables, VLOOKUP functions, and Excel's analytical tools. For smaller datasets or initial explorations, Excel remains a valuable tool in his workflow, complementing his more advanced technical approaches."
    // Excel in data analytics context, fits in dataAnalyticsResponses
  },

  // Specific Analytical Approaches
  {
    keywords: ['predictive analytics', 'prediction', 'forecasting'],
    response: "Vathsaran's approach to predictive analytics combines statistical methods with business context. He's worked with time series analysis for forecasting, regression models for outcome prediction, and classification algorithms for category prediction. His focus is on creating interpretable models that balance accuracy with practical usability, ensuring predictions can be easily understood and applied by decision-makers."
    // Predictive analytics techniques, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['descriptive analytics', 'business metrics', 'kpis'],
    response: "Vathsaran excels at descriptive analytics, transforming raw data into meaningful business metrics and KPIs. In his E-commerce Analytics Tool, he designed comprehensive dashboards showing customer acquisition costs, lifetime value, conversion rates, and product performance metrics. He focuses on creating clear, actionable metrics that align with strategic goals and provide actionable insights."
    // Descriptive analytics and KPIs, fits in dataAnalyticsResponses
  },
  {
    keywords: ['segmentation', 'clustering', 'customer segments'],
    response: "In the E-commerce Analytics Tool project, Vathsaran implemented customer segmentation using clustering algorithms to identify distinct customer groups based on purchase behavior, preferences, and engagement patterns. This allowed for targeted marketing strategies and personalized customer experiences. His approach combines algorithmic segmentation with business logic to ensure segments are both statistically valid and commercially meaningful."
    // Segmentation in analytics, belongs in dataAnalyticsResponses
  },

  // Data Visualization Specifics
  {
    keywords: ['visualization principles', 'data viz principles', 'visualization best practices'],
    response: "Vathsaran applies key data visualization principles in his work: 1) Focus on the core message, 2) Choose appropriate chart types for the data, 3) Minimize clutter and maximize data-to-ink ratio, 4) Use color purposefully, 5) Design for the intended audience, and 6) Enable interactive exploration when beneficial. His background in design enhances his visualizations, making complex data accessible without sacrificing accuracy."
    // Visualization principles in analytics, fits in dataAnalyticsResponses
  },
  {
    keywords: ['interactive dashboards', 'interactive visualizations'],
    response: "Vathsaran creates interactive dashboards that allow users to explore data dynamically. His Data Visualization Dashboard project features filters, drill-down capabilities, and parameterized views that enable users to answer their own questions through data exploration. He balances guided insights with exploratory freedom, ensuring dashboards are both informative and engaging for both technical and non-technical users."
    // Interactive dashboards in analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['data storytelling', 'narrative visualization', 'storytelling with data'],
    response: "Data storytelling is where Vathsaran's analytics and design backgrounds converge most powerfully. He crafts data narratives that guide audiences through insights in a compelling, structured way. This involves sequencing visualizations logically, highlighting key patterns, providing necessary context, and creating a cohesive flow that leads to actionable conclusions. His approach ensures data doesn't just inform but persuades and motivates action."
    // Data storytelling in analytics, fits in dataAnalyticsResponses
  },

  // Business Application of Data
  {
    keywords: ['business impact', 'data roi', 'business value'],
    response: "Vathsaran focuses on generating tangible business impact from data. His E-commerce Analytics Tool helped increase customer retention by 18% through targeted interventions, while his inventory analysis reduced stockouts by 25%. He approaches every project with a clear understanding of business objectives, ensuring analyses directly address key performance indicators and deliver measurable return on investment."
    // Business impact of analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['decision making', 'data-driven decisions'],
    response: "Vathsaran believes effective data analytics should enhance decision-making at all levels. His visualization work emphasizes clarity and actionability, helping stakeholders move quickly from insight to action. He designs analytics outputs specifically for decision support, balancing comprehensive information with focused recommendations, and adapting detail levels for different decision-makers from executives to operational teams."
    // Data-driven decision-making, fits in dataAnalyticsResponses
  },
  {
    keywords: ['data strategy', 'analytics strategy'],
    response: "While still developing expertise in organizational data strategy, Vathsaran understands the importance of aligning analytics work with broader business goals. He approaches projects with consideration for how they fit into the organization's data ecosystem and long-term analytics needs, focusing on sustainable solutions that build analytics capabilities rather than one-off analyses."
    // Data strategy in analytics, belongs in dataAnalyticsResponses
  },

  // Industry-Specific Data Analytics
  {
    keywords: ['retail analytics', 'e-commerce data', 'retail data'],
    response: "Vathsaran has specific experience with retail and e-commerce analytics. His E-commerce Analytics Tool project involved customer segmentation, purchase pattern analysis, product recommendation systems, and inventory optimization. He's familiar with key metrics like average order value, customer acquisition cost, and lifetime value, as well as analytical approaches for pricing optimization and market basket analysis."
    // Retail analytics, clearly data-specific, fits in dataAnalyticsResponses
  },
  {
    keywords: ['hr analytics', 'people analytics', 'workforce data'],
    response: "Vathsaran's Leave Management System project demonstrated his capability in HR analytics. The system tracked leave patterns, identified departments with unusual absence rates, and provided predictive insights on staffing needs. While not his primary focus, this experience gave him familiarity with workforce analytics applications and HR data structures."
    // HR analytics, belongs in dataAnalyticsResponses
  },

  // Learning and Growth (Data Analytics Specific)
  {
    keywords: ['data trends', 'analytics trends', 'future of data'],
    response: "Vathsaran stays current with data analytics trends including the rise of augmented analytics, responsible AI, embedded analytics in applications, and data democratization. He's particularly interested in how visualization techniques are evolving to handle increasingly complex datasets and how design principles can make advanced analytics more accessible to non-technical users."
    // Trends specific to data analytics, fits in dataAnalyticsResponses
  },

  // Interesting Data Questions
  {
    keywords: ['favorite visualization', 'best chart', 'best graph'],
    response: "Vathsaran has a particular appreciation for thoughtfully designed interactive visualizations that reveal multiple dimensions of data. While he values classic forms like well-constructed bar and line charts for their clarity, he enjoys creating more innovative forms like network diagrams, treemaps, and custom visualizations when they're appropriate for the data. His design background helps him know when to stick with proven formats and when to innovate."
    // Visualization preferences in analytics, belongs in dataAnalyticsResponses
  },
  {
    keywords: ['data challenge', 'analytics problem', 'difficult data'],
    response: "One of Vathsaran's most challenging data projects involved reconciling inconsistent customer data from multiple systems for the E-commerce Analytics Tool. He developed a robust entity resolution system that used fuzzy matching and machine learning to create a unified customer view across platforms. This challenge taught him valuable lessons about data integration and quality management in real-world environments."
    // Data analytics challenge, fits in dataAnalyticsResponses
  },
  {
    keywords: ['data mistake', 'analytics error', 'common mistake'],
    response: "Vathsaran believes the most common mistake in data projects is rushing to analysis without properly understanding business context and data limitations. He advocates for thorough exploratory analysis and stakeholder consultation before drawing conclusions. He's learned from experience that skipping these steps can lead to technically correct analyses that miss the actual business need or fail to account for important data nuances."
    // Common mistakes in data analytics, belongs in dataAnalyticsResponses
  },

  // Learning and Growth (Moved from knowledgeBase as it’s analytics-specific)
  {
    keywords: ['learning', 'studying', 'improving'],
    response: "As a data analytics student, Vathsaran is actively expanding his skills in advanced statistical methods, machine learning, and big data technologies. He takes a structured approach to learning, combining formal education with hands-on projects and independent study. Current focus areas include machine learning algorithms, cloud-based analytics platforms, and advanced data visualization techniques."
    // Learning specific to data analytics skills, fits better in dataAnalyticsResponses
  }
];

knowledgeBase.push(...dataAnalyticsResponses);

let conversationContext = {
    topics: [],
    recentFocus: null,
    greeting: false,
    questionCount: 0,
    preferredArea: null
};

/**
 * Generates bot response based on user message
 * @param {string} message - User input
 * @returns {string} Bot response
 */
function getBotResponse(message) {
    const lowerMessage = message.toLowerCase();
    conversationContext.questionCount++;
    if (['hello', 'hi', 'hey', 'greetings'].some(word => lowerMessage.includes(word)) && !conversationContext.greeting) {
        conversationContext.greeting = true;
    }
    detectUserInterest(lowerMessage);
    let response = findDirectResponse(lowerMessage) || generateContextualResponse(lowerMessage);
    updateConversationContext(lowerMessage, response);
    return response;
}

function findDirectResponse(message) {
    const sortedResponses = [...knowledgeBase].sort((a, b) => {
        if (conversationContext.preferredArea) {
            const aRelated = a.keywords.some(k => k.includes(conversationContext.preferredArea));
            const bRelated = b.keywords.some(k => k.includes(conversationContext.preferredArea));
            if (aRelated && !bRelated) return -1;
            if (!aRelated && bRelated) return 1;
        }
        return b.keywords.join(' ').length - a.keywords.join(' ').length;
    });
    for (const item of sortedResponses) {
        if (item.keywords.some(keyword => message.includes(keyword))) return item.response;
    }
    return null;
}

function generateContextualResponse(message) {
    if (conversationContext.recentFocus) {
        const focusResponses = knowledgeBase.filter(item => item.keywords.some(k => k.includes(conversationContext.recentFocus)));
        if (focusResponses.length > 0) return `Based on our conversation about ${conversationContext.recentFocus}, ${focusResponses[0].response}`;
    }
    if (conversationContext.preferredArea) {
        const areaResponses = knowledgeBase.filter(item => item.keywords.some(k => k.includes(conversationContext.preferredArea)));
        if (areaResponses.length > 0) {
            const randomIndex = Math.floor(Math.random() * areaResponses.length);
            return `Since you're interested in ${conversationContext.preferredArea}, you might want to know that ${areaResponses[randomIndex].response}`;
        }
    }
    if (conversationContext.greeting && conversationContext.questionCount <= 2) {
        return "I'd be happy to tell you about Vathsaran's work in data analytics and design...";
    }
    return knowledgeBase.find(item => item.keywords.includes('default')).response;
}

function detectUserInterest(message) {
    const interestAreas = [
        { area: 'data analytics', keywords: ['data', 'analytics', 'analysis', 'statistics', 'python', 'sql'] },
        { area: 'design', keywords: ['design', 'graphic', 'creative', 'visual', 'adobe', 'photoshop'] },
        { area: 'projects', keywords: ['project', 'portfolio', 'work', 'case study', 'example'] },
        { area: 'skills', keywords: ['skill', 'ability', 'proficiency', 'capable', 'experience'] }
    ];
    for (const interest of interestAreas) {
        if (interest.keywords.some(k => message.includes(k))) {
            conversationContext.preferredArea = interest.area;
            break;
        }
    }
}

function updateConversationContext(message, response) {
    const topicWords = message.split(' ')
        .filter(word => word.length > 3)
        .filter(word => !['what', 'when', 'where', 'which', 'would', 'could'].includes(word));
    if (topicWords.length > 0) {
        conversationContext.topics = [...new Set([...conversationContext.topics, ...topicWords])];
        conversationContext.recentFocus = topicWords[0];
    }
    if (conversationContext.topics.length > 10) conversationContext.topics = conversationContext.topics.slice(-10);
}

function getTimeBasedGreeting() {
    const hour = new Date().getHours();
    if (hour < 12) return "Good morning! I'm Jarvis, Vathsaran's digital assistant.";
    else if (hour < 18) return "Good afternoon! I'm Jarvis, Vathsaran's digital assistant.";
    else return "Good evening! I'm Jarvis, Vathsaran's digital assistant.";
}

function resetChatbotContext() {
    conversationContext = { topics: [], recentFocus: null, greeting: false, questionCount: 0, preferredArea: null };
}

/**
 * Initializes mobile chatbot functionality with consistent behavior across all pages
 */
function initMobileChatbot() {
    const chatbotToggle = document.getElementById('chatbotToggle');
    const closeChatbotBtn = document.getElementById('closeChatbot');
    const chatbot = document.getElementById('chatbot');
    const chatMessages = document.getElementById('chatMessages');
    const userInput = document.getElementById('userInput');
    const sendMessageBtn = document.getElementById('sendMessage');

    // If chatbot elements don't exist, exit early
    if (!chatbot || !closeChatbotBtn) return;

    // Create chatbot toggle button if it doesn't exist (for non-home pages)
    if (!chatbotToggle) {
        const newChatbotToggle = document.createElement('button');
        newChatbotToggle.id = 'chatbotToggle';
        newChatbotToggle.className = 'chatbot-toggle';
        newChatbotToggle.innerHTML = '<i class="fas fa-comments"></i>';
        document.body.appendChild(newChatbotToggle);
        
        // Update the reference
        chatbotToggleBtn = newChatbotToggle;
    } else {
        chatbotToggleBtn = chatbotToggle;
    }

    // Make sure the chatbot is initially hidden and toggle is visible
    chatbot.style.display = 'none';
    chatbotToggleBtn.style.display = 'flex';

    const isMobile = () => window.innerWidth <= 768 || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

    // Open chatbot
    chatbotToggleBtn.addEventListener('click', () => {
        chatbot.style.display = 'flex';
        chatbotToggleBtn.style.display = 'none';

        if (isMobile()) {
            document.body.classList.add('chatbot-open');
            chatbot.classList.add('opening');
            setTimeout(() => chatbot.classList.remove('opening'), 300);
        }

        // Add initial message if the chat is empty
        if (chatMessages.children.length === 0) {
            const initialMessage = document.createElement('div');
            initialMessage.className = 'chat-message bot-message';
            initialMessage.textContent = getTimeBasedGreeting();
            chatMessages.appendChild(initialMessage);
        }

        setTimeout(() => {
            userInput.focus();
            scrollToLatestMessage();
        }, 400);
    });

    // Close chatbot
    closeChatbotBtn.addEventListener('click', () => {
        if (isMobile()) {
            chatbot.classList.add('closing');
            setTimeout(() => {
                chatbot.style.display = 'none';
                chatbotToggleBtn.style.display = 'flex';
                chatbot.classList.remove('closing');
                document.body.classList.remove('chatbot-open');
            }, 300);
        } else {
            chatbot.style.display = 'none';
            chatbotToggleBtn.style.display = 'flex';
        }
    });

    function handleKeyboardVisibility() {
        if (!isMobile()) return;
        let initialWindowHeight = window.innerHeight;
        let isKeyboardOpen = false;

        window.addEventListener('resize', () => {
            const newHeight = window.innerHeight;
            if (newHeight < initialWindowHeight * 0.8) {
                if (!isKeyboardOpen) {
                    isKeyboardOpen = true;
                    chatbot.classList.add('keyboard-open');
                    document.body.classList.add('keyboard-open');
                    const keyboardHeight = initialWindowHeight - newHeight;
                    document.documentElement.style.setProperty('--keyboard-height', `${keyboardHeight}px`);
                    setTimeout(() => {
                        scrollToLatestMessage();
                        // Ensure chat input is visible by scrolling to it if needed
                        const chatInput = document.querySelector('.chat-input');
                        if (chatInput) chatInput.scrollIntoView(false);
                    }, 300);
                }
            } else if (isKeyboardOpen && newHeight > initialWindowHeight * 0.8) {
                isKeyboardOpen = false;
                chatbot.classList.remove('keyboard-open');
                document.body.classList.remove('keyboard-open');
                document.documentElement.style.removeProperty('--keyboard-height');
            }
        });

        userInput.addEventListener('focus', () => {
            if (isMobile()) {
                setTimeout(() => {
                    chatbot.classList.add('keyboard-open');
                    document.body.classList.add('keyboard-open');
                    scrollToLatestMessage();
                }, 300);
            }
        });

        userInput.addEventListener('blur', () => {
            if (isMobile()) {
                setTimeout(() => {
                    chatbot.classList.remove('keyboard-open');
                    document.body.classList.remove('keyboard-open');
                }, 100);
            }
        });
    }

    function scrollToLatestMessage() {
        if (chatMessages) chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    if (chatMessages) {
        chatMessages.addEventListener('touchmove', (e) => e.stopPropagation(), { passive: true });
    }

    sendMessageBtn.addEventListener('click', sendMessage);
    userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    function sendMessage() {
        const message = userInput.value.trim();
        if (message) {
            addMessage(message, true);
            userInput.value = '';
            userInput.focus();
            addTypingIndicator();
            setTimeout(() => {
                removeTypingIndicator();
                const response = getBotResponse(message);
                addMessage(response, false);
            }, 1000 + Math.random() * 1000);
        }
    }

    function addMessage(text, isUser) {
        const messageElement = document.createElement('div');
        messageElement.className = `chat-message ${isUser ? 'user-message' : 'bot-message'}`;
        messageElement.textContent = text;
        chatMessages.appendChild(messageElement);
        scrollToLatestMessage();
    }

    function addTypingIndicator() {
        const indicator = document.createElement('div');
        indicator.className = 'chat-message bot-message typing-indicator';
        indicator.id = 'typingIndicator';
        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('span');
            indicator.appendChild(dot);
        }
        chatMessages.appendChild(indicator);
        scrollToLatestMessage();
    }

    function removeTypingIndicator() {
        const indicator = document.getElementById('typingIndicator');
        if (indicator) indicator.remove();
    }

    function setupSafeAreas() {
        const existingViewport = document.querySelector('meta[name="viewport"]');
        if (existingViewport) {
            existingViewport.content += ',viewport-fit=cover';
        } else {
            const meta = document.createElement('meta');
            meta.name = 'viewport';
            meta.content = 'width=device-width, initial-scale=1, viewport-fit=cover';
            document.head.appendChild(meta);
        }
        const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
        if (isIOS) document.documentElement.classList.add('ios-device');
    }

    handleKeyboardVisibility();
    setupSafeAreas();
}

function initLogoEffects() {
    const logo = document.querySelector('.logo');
    if (!logo) return;
  
    // Typing Effect
    const text = logo.getAttribute('data-text');
    logo.textContent = ''; // Clear initial text
    let i = 0;
    function type() {
      if (i < text.length) {
        logo.textContent += text.charAt(i);
        i++;
        setTimeout(type, 100); // Typing speed
      }
    }
    type();
  
    // Glitch Effect
    setInterval(() => {
      if (Math.random() > 0.8) {
        anime({
          targets: logo,
          opacity: [1, 0.7, 1],
          translateX: [-2, 2, 0],
          translateY: [1, -1, 0],
          duration: 300,
          easing: 'easeInOutQuad'
        });
      }
    }, 4000);
  }
  
  // Run it on DOM load
  document.addEventListener('DOMContentLoaded', initLogoEffects);

// ==========================================================================
// Hologram Frame Interactions
// ==========================================================================

/**
 * Initializes touch functionality for hologram frames
 */
/**
 * Enhanced initialization for hologram frames with bottom-to-top lifting effect
 */
/**
 * Initializes hologram frames with visual effects while preserving interaction with other elements
 */
function initHologramFrames() {
    const frames = document.querySelectorAll('.hologram-frame');
    
    if (!frames.length) return;
    
    // Add CSS for hologram effects without breaking other interactions
    const styleElement = document.createElement('style');
    styleElement.textContent = `
      /* Fix z-index stacking without breaking interactions */
      .hologram-frame {
        position: relative;
        z-index: 5;
        pointer-events: auto;
      }
      
      /* Ensure overlays don't block clicks */
      .hologram-overlay {
        pointer-events: none !important;
      }
      
      /* Enhanced hover/active state */
      .hologram-frame.touch-active {
        box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4), 
                    0 0 30px var(--primary-color), 
                    0 0 40px rgba(0, 191, 255, 0.3) inset;
        transform: translateY(-10px) scale(1.02);
      }
      
      /* Random glitch animation */
      @keyframes glitchAnimation {
        0% { opacity: 1; }
        10% { opacity: 0.8; transform: translate(-2px, 1px); }
        20% { opacity: 1; transform: translate(0); }
        30% { opacity: 1; }
        35% { opacity: 0.9; transform: translate(1px, -1px); }
        40% { opacity: 1; transform: translate(0); }
        100% { opacity: 1; }
      }
      
      /* Fix chatbot interaction issues */
      #chatbot {
        z-index: 2000 !important;
        pointer-events: auto !important;
      }
      
      #chatbot .chat-header,
      #chatbot .chat-messages,
      #chatbot .chat-input {
        z-index: 2001 !important;
        pointer-events: auto !important;
      }
      
      #chatbot input,
      #chatbot button {
        z-index: 2002 !important;
        pointer-events: auto !important;
      }
      
      #closeChatbot {
        z-index: 2003 !important;
        pointer-events: auto !important;
      }
      
      /* Ensure chatbot takes precedence over particles */
      #particles-js {
        z-index: 1 !important;
      }
    `;
    
    // Check if style already exists to prevent duplicates
    const existingStyle = document.querySelector('style[data-hologram-styles]');
    if (!existingStyle) {
      styleElement.setAttribute('data-hologram-styles', 'true');
      document.head.appendChild(styleElement);
    }
    
    frames.forEach(frame => {
      // Skip already initialized frames
      if (frame.dataset.initialized === 'true') return;
      frame.dataset.initialized = 'true';
      
      // Reset any transform that might have been applied
      frame.style.transform = '';
      
      const isTouchDevice = 'ontouchstart' in window || 
                            navigator.maxTouchPoints > 0 || 
                            navigator.msMaxTouchPoints > 0;
      
      // Find and adjust the scan line animation
      const scanLine = frame.querySelector('.hologram-scan-line');
      if (scanLine) {
        scanLine.style.animationDelay = `${Math.random() * -2}s`;
      }
      
      // Add click handler using event delegation approach
      // This prevents excessive event listeners
      if (!frame._clickHandlerAdded) {
        frame._clickHandlerAdded = true;
        
        frame.addEventListener('click', function(e) {
          const wasActive = this.classList.contains('touch-active');
          this.classList.toggle('touch-active');
          
          // Also toggle the overlay for visual effect
          const overlay = this.querySelector('.hologram-overlay');
          if (overlay) {
            if (wasActive) {
              overlay.style.transform = '';
            } else {
              overlay.style.transform = 'translateY(-100%)';
            }
          }
        });
      }
      
      // Touch-specific functionality - use passive listeners for better performance
      if (isTouchDevice) {
        const hologramOverlay = frame.querySelector('.hologram-overlay');
        
        if (hologramOverlay && !frame._touchHandlerAdded) {
          frame._touchHandlerAdded = true;
          
          // Use touchend instead of touchstart for better mobile experience
          frame.addEventListener('touchend', function(event) {
            // Don't prevent default here to allow scrolling
            const isActive = this.classList.contains('touch-active');
            
            if (!isActive) {
              hologramOverlay.style.transform = 'translateY(-100%)';
              this.classList.add('touch-active');
            } else {
              hologramOverlay.style.transform = '';
              this.classList.remove('touch-active');
            }
          }, { passive: true });
        }
      }
      
      // Add subtle 3D effect on mouse move (for desktop only)
      // Use a more efficient approach with throttling
      if (!frame._mouseMoveHandlerAdded && window.innerWidth > 768) {
        frame._mouseMoveHandlerAdded = true;
        
        let ticking = false;
        
        frame.addEventListener('mousemove', function(e) {
          if (!ticking) {
            window.requestAnimationFrame(() => {
              const rect = this.getBoundingClientRect();
              const x = e.clientX - rect.left;
              const y = e.clientY - rect.top;
              
              // Calculate rotation based on mouse position
              const xRotation = 5 * ((y - rect.height / 2) / rect.height);
              const yRotation = -5 * ((x - rect.width / 2) / rect.width);
              
              // Apply subtle 3D rotation effect
              this.style.transform = `perspective(1000px) rotateX(${xRotation}deg) rotateY(${yRotation}deg) translateY(-5px)`;
              
              // Adjust overlay animation based on mouse position
              const overlay = this.querySelector('.hologram-overlay');
              if (overlay && !this.classList.contains('touch-active')) {
                const progressY = Math.min(100, Math.max(0, ((rect.height - y) / rect.height) * 120));
                overlay.style.transform = `translateY(-${progressY}%)`;
              }
              
              ticking = false;
            });
            
            ticking = true;
          }
        }, { passive: true });
        
        // Reset transform and overlay on mouse out
        frame.addEventListener('mouseleave', function() {
          this.style.transform = '';
          
          // Reset overlay if not in touch-active state
          if (!this.classList.contains('touch-active')) {
            const overlay = this.querySelector('.hologram-overlay');
            if (overlay) {
              overlay.style.transform = '';
            }
          }
        }, { passive: true });
      }
      
      // Add random glitch effect without using external libraries
      // This prevents potential conflicts
      if (!frame._glitchIntervalAdded) {
        frame._glitchIntervalAdded = true;
        
        const glitchElement = frame.querySelector('.hologram-glitch');
        if (glitchElement) {
          // Use a more efficient setInterval approach
          const glitchInterval = setInterval(() => {
            if (Math.random() > 0.7) {
              // Apply random glitch effect
              glitchElement.style.opacity = '0.3';
              glitchElement.style.transform = 'translate(-2px, 1px)';
              
              // Reset after animation
              setTimeout(() => {
                glitchElement.style.opacity = '0.7';
                glitchElement.style.transform = '';
              }, 400);
            }
          }, 3000);
          
          // Store interval ID for potential cleanup
          frame._glitchInterval = glitchInterval;
        }
      }
    });
  
    // Make sure particles are behind content but still interactive
    const particlesElement = document.getElementById('particles-js');
    if (particlesElement) {
      particlesElement.style.zIndex = '1';
      // Allow interaction with particles but ensure they don't block other elements
      particlesElement.style.pointerEvents = 'auto';
    }
    
    // Ensure chatbot and buttons have proper z-index and pointer-events
    const chatbotToggle = document.getElementById('chatbotToggle');
    const chatbot = document.getElementById('chatbot');
    const scrollToTopBtn = document.getElementById('scrollToTopBtn');
    
    if (chatbotToggle) {
      chatbotToggle.style.zIndex = '1000';
      chatbotToggle.style.position = 'fixed';
      chatbotToggle.style.pointerEvents = 'auto';
    }
    
    if (chatbot) {
      // Make sure the chatbot has an even higher z-index than the toggle button
      chatbot.style.zIndex = '2000';
      chatbot.style.pointerEvents = 'auto';
      
      // Ensure all chatbot children are interactive
      const chatElements = chatbot.querySelectorAll('*');
      chatElements.forEach(el => {
        el.style.pointerEvents = 'auto';
      });
      
      // Make sure the chat input area is fully interactive
      const chatInput = chatbot.querySelector('.chat-input');
      const chatMessages = chatbot.querySelector('.chat-messages');
      const chatHeader = chatbot.querySelector('.chat-header');
      
      if (chatInput) {
        chatInput.style.zIndex = '2001';
        chatInput.style.pointerEvents = 'auto';
        
        // Ensure the input and button are interactive
        const inputField = chatInput.querySelector('input');
        const sendButton = chatInput.querySelector('button');
        
        if (inputField) {
          inputField.style.pointerEvents = 'auto';
        }
        
        if (sendButton) {
          sendButton.style.pointerEvents = 'auto';
        }
      }
      
      if (chatMessages) {
        chatMessages.style.zIndex = '2001';
        chatMessages.style.pointerEvents = 'auto';
      }
      
      if (chatHeader) {
        chatHeader.style.zIndex = '2001';
        chatHeader.style.pointerEvents = 'auto';
        
        const closeButton = chatHeader.querySelector('button');
        if (closeButton) {
          closeButton.style.zIndex = '2002';
          closeButton.style.pointerEvents = 'auto';
        }
      }
    }
    
    if (scrollToTopBtn) {
      scrollToTopBtn.style.zIndex = '1000';
      scrollToTopBtn.style.position = 'fixed';
      scrollToTopBtn.style.pointerEvents = 'auto';
    }
  }
  
  // Clean up function to prevent memory leaks
  function cleanupHologramFrames() {
    const frames = document.querySelectorAll('.hologram-frame');
    
    frames.forEach(frame => {
      // Clear any intervals to prevent memory leaks
      if (frame._glitchInterval) {
        clearInterval(frame._glitchInterval);
        frame._glitchInterval = null;
      }
    });
  }
  
  // Add this cleanup on page unload
  window.addEventListener('beforeunload', cleanupHologramFrames);
  
  // If the document is already loaded, initialize immediately
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    initHologramFrames();
  } else {
    // Otherwise wait for the DOM to be ready
    document.addEventListener('DOMContentLoaded', initHologramFrames);
  }
  
  // Re-initialize on window resize to handle orientation changes
  window.addEventListener('resize', function() {
    // Debounce the resize event
    clearTimeout(this._resizeTimer);
    this._resizeTimer = setTimeout(initHologramFrames, 200);
  });
  
  // Add special handling for chatbot interactions
  function fixChatbotInteractions() {
    const chatbot = document.getElementById('chatbot');
    const chatbotToggle = document.getElementById('chatbotToggle');
    
    if (!chatbot || !chatbotToggle) return;
    
    // Fix chatbot toggle button click handler
    if (!chatbotToggle._fixedClickHandler) {
      const originalClickHandler = chatbotToggle.onclick;
      
      chatbotToggle.onclick = function(e) {
        // Call the original handler if it exists
        if (originalClickHandler) {
          originalClickHandler.call(this, e);
        }
        
        // Make sure chatbot is fully interactive when opened
        setTimeout(() => {
          chatbot.style.zIndex = '2000';
          chatbot.style.pointerEvents = 'auto';
          
          const chatElements = chatbot.querySelectorAll('*');
          chatElements.forEach(el => {
            el.style.pointerEvents = 'auto';
          });
        }, 100);
      };
      
      chatbotToggle._fixedClickHandler = true;
    }
    
    // Ensure chat input is always interactive
    const userInput = document.getElementById('userInput');
    const sendMessageBtn = document.getElementById('sendMessage');
    
    if (userInput) {
      userInput.style.pointerEvents = 'auto';
      userInput.style.zIndex = '2002';
      
      // Add focus events to ensure chatbot stays interactive
      userInput.addEventListener('focus', function() {
        chatbot.style.zIndex = '2000';
        this.style.zIndex = '2002';
      });
    }
    
    if (sendMessageBtn) {
      sendMessageBtn.style.pointerEvents = 'auto';
      sendMessageBtn.style.zIndex = '2002';
    }
    
    // Fix close button interaction
    const closeChatbotBtn = document.getElementById('closeChatbot');
    if (closeChatbotBtn) {
      closeChatbotBtn.style.pointerEvents = 'auto';
      closeChatbotBtn.style.zIndex = '2003';
    }
  }
  
  // Call this function when document is ready
  document.addEventListener('DOMContentLoaded', function() {
    initHologramFrames();
    fixChatbotInteractions();
  });
  
  // Also fix the chatbot after the page is fully loaded
  window.addEventListener('load', fixChatbotInteractions);

// Make sure this function is called when the DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  initHologramFrames();
});

// Ensure the function is called when the DOM is ready
document.addEventListener('DOMContentLoaded', initMobileChatbot);

// Enhanced UI Features for Portfolio Website
document.addEventListener('DOMContentLoaded', function() {
    // Initialize UI enhancements
    initScrollIndicator();
    initSectionFadeIn();
    enhanceBackToTopButton();
    initPageLoader();
    initTooltips();
    initSkillBars();
    initEnhancedCards();
    initNotificationSystem();
    addSkipToContentLink();
    enhanceNavigation();
    initHologramFrames();
});

// Enhanced Navigation Effects
function enhanceNavigation() {
    // Get all navigation links
    const navLinks = document.querySelectorAll('.nav-links a');
    
    // Add active class to current page
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    
    navLinks.forEach(link => {
      // Add hover effect with dynamic underline
      link.addEventListener('mouseenter', function() {
        // Create underline element if it doesn't exist
        if (!this.querySelector('.nav-underline')) {
          const underline = document.createElement('span');
          underline.className = 'nav-underline';
          underline.style.position = 'absolute';
          underline.style.bottom = '0';
          underline.style.left = '0';
          underline.style.width = '0';
          underline.style.height = '2px';
          underline.style.background = 'linear-gradient(90deg, var(--primary-color), var(--accent-color))';
          underline.style.transition = 'width 0.3s ease';
          this.style.position = 'relative';
          this.appendChild(underline);
        }
        
        // Animate the underline
        const underline = this.querySelector('.nav-underline');
        underline.style.width = '100%';
      });
      
      link.addEventListener('mouseleave', function() {
        const underline = this.querySelector('.nav-underline');
        if (underline && !this.classList.contains('active')) {
          underline.style.width = '0';
        }
      });
      
      // Check if this is the active page
      const href = link.getAttribute('href');
      if (href === currentPage) {
        link.classList.add('active');
        
        // Add permanent underline for active link
        const underline = document.createElement('span');
        underline.className = 'nav-underline active';
        underline.style.position = 'absolute';
        underline.style.bottom = '0';
        underline.style.left = '0';
        underline.style.width = '100%';
        underline.style.height = '2px';
        underline.style.background = 'linear-gradient(90deg, var(--primary-color), var(--accent-color))';
        link.style.position = 'relative';
        link.appendChild(underline);
      }
    });
  }

// Scroll Progress Indicator
function initScrollIndicator() {
    const scrollIndicator = document.createElement('div');
    scrollIndicator.className = 'scroll-indicator';
    document.body.appendChild(scrollIndicator);

    window.addEventListener('scroll', function() {
        const winScroll = document.body.scrollTop || document.documentElement.scrollTop;
        const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        const scrolled = (winScroll / height) * 100;
        scrollIndicator.style.width = scrolled + '%';
    });
}

// Fade-in sections on scroll
function initSectionFadeIn() {
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.classList.add('section-fade-in');
    });

    const checkIfInView = () => {
        const sections = document.querySelectorAll('.section-fade-in');
        sections.forEach(section => {
            const rect = section.getBoundingClientRect();
            const isInView = (
                rect.top <= window.innerHeight * 0.8 &&
                rect.bottom >= 0
            );
            
            if (isInView) {
                section.classList.add('visible');
            }
        });
    };

    // Check on initial load
    setTimeout(checkIfInView, 300);
    
    // Check on scroll
    window.addEventListener('scroll', debounce(checkIfInView, 50));
}

// Enhanced Back-to-Top Button
function enhanceBackToTopButton() {
    const scrollToTopBtn = document.getElementById("scrollToTopBtn");
    if (scrollToTopBtn) {
        scrollToTopBtn.classList.add('enhanced');
        
        window.addEventListener('scroll', function() {
            if (document.body.scrollTop > 200 || document.documentElement.scrollTop > 200) {
                scrollToTopBtn.classList.add('visible');
            } else {
                scrollToTopBtn.classList.remove('visible');
            }
        });
    }
}

// Page Loading Animation
function initPageLoader() {
    // Create loader element
    const loader = document.createElement('div');
    loader.className = 'page-loader';
    loader.innerHTML = '<div class="loader-spinner"></div>';
    document.body.appendChild(loader);
    
    // Hide loader when page is fully loaded
    window.addEventListener('load', function() {
        loader.classList.add('loader-hidden');
        setTimeout(() => {
            loader.remove();
        }, 500);
    });
    
    // For demo purposes, remove loader after a minimum time
    setTimeout(() => {
        loader.classList.add('loader-hidden');
        setTimeout(() => {
            loader.remove();
        }, 500);
    }, 1000);
}

// Tooltip Initialization
function initTooltips() {
    // Find elements with data-tooltip attribute
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        // Make the element a tooltip container
        element.classList.add('tooltip');
        
        // Create tooltip text element
        const tooltipText = document.createElement('span');
        tooltipText.className = 'tooltip-text';
        tooltipText.textContent = element.getAttribute('data-tooltip');
        
        // Add tooltip text to element
        element.appendChild(tooltipText);
    });
}

// Enhanced Skill Bars
function initSkillBars() {
    const skillBars = document.querySelectorAll('.skill-bar');
    
    skillBars.forEach(bar => {
        bar.classList.add('enhanced');
        
        // Reset width to 0 initially
        const originalWidth = bar.style.width;
        bar.style.width = '0%';
        
        const observer = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Animate to original width when visible
                    setTimeout(() => {
                        bar.style.width = originalWidth;
                    }, 200);
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });
        
        observer.observe(bar);
    });
}

// Enhanced Project Cards
function initEnhancedCards() {
    const projectCards = document.querySelectorAll('.project-card');
    const techTags = document.querySelectorAll('.tech-tag');
    
    projectCards.forEach(card => {
        card.classList.add('enhanced');
    });
    
    techTags.forEach(tag => {
        tag.classList.add('enhanced');
    });
}

// Notification System
function initNotificationSystem() {
    // Create notification container if it doesn't exist
    let notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.style.position = 'fixed';
        notificationContainer.style.top = '20px';
        notificationContainer.style.right = '20px';
        notificationContainer.style.zIndex = '2000';
        document.body.appendChild(notificationContainer);
    }

    // Add notification method to window for easy access
    window.showNotification = function(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        
        // Set appropriate icon based on type
        let icon = '';
        switch(type) {
            case 'success':
                icon = '<i class="fas fa-check-circle notification-icon"></i>';
                break;
            case 'error':
                icon = '<i class="fas fa-exclamation-circle notification-icon"></i>';
                break;
            case 'warning':
                icon = '<i class="fas fa-exclamation-triangle notification-icon"></i>';
                break;
            case 'info':
            default:
                icon = '<i class="fas fa-info-circle notification-icon"></i>';
                break;
        }
        
        notification.innerHTML = `${icon}<span>${message}</span>`;
        
        // Add a futuristic style element
        const glowLine = document.createElement('div');
        glowLine.style.position = 'absolute';
        glowLine.style.bottom = '0';
        glowLine.style.left = '0';
        glowLine.style.height = '2px';
        glowLine.style.width = '0';
        glowLine.style.transition = 'width 2s linear';
        
        // Set color based on notification type
        switch(type) {
            case 'success':
                glowLine.style.background = 'linear-gradient(to right, transparent, #4CAF50, transparent)';
                break;
            case 'error':
                glowLine.style.background = 'linear-gradient(to right, transparent, #F44336, transparent)';
                break;
            case 'warning':
                glowLine.style.background = 'linear-gradient(to right, transparent, #FF9800, transparent)';
                break;
            case 'info':
            default:
                glowLine.style.background = 'linear-gradient(to right, transparent, #2196F3, transparent)';
                break;
        }
        
        notification.style.position = 'relative';
        notification.style.overflow = 'hidden';
        notification.appendChild(glowLine);
        
        notificationContainer.appendChild(notification);
        
        // Show notification
        setTimeout(() => {
            notification.classList.add('show');
            glowLine.style.width = '100%'; // Start the progress indicator
        }, 10);
        
        // Remove notification after duration
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, duration);
};

    // Show a welcome notification only on the first visit or homepage
    setTimeout(() => {
        // Check if we're on the homepage
        const isHomePage = window.location.pathname === '/' || 
                            window.location.pathname.endsWith('index.html') || 
                            window.location.pathname === '/index' ||
                            window.location.href.indexOf('index.html') > -1;
        
        // Check if welcome notification has been shown before
        const hasShownWelcome = sessionStorage.getItem('welcomeShown');
        
        if ((isHomePage || !hasShownWelcome) && !hasShownWelcome) {
            window.showNotification('Welcome to my portfolio!', 'info', 5000);
            sessionStorage.setItem('welcomeShown', 'true');
        }
    }, 2000);

    // Example usage:
    // Uncomment the following line to test notification
    // setTimeout(() => { window.showNotification('Welcome to my portfolio!', 'info', 5000); }, 2000);
}

// Add Skip to Content Link for Accessibility
function addSkipToContentLink() {
    const skipLink = document.createElement('a');
    skipLink.className = 'skip-to-content';
    skipLink.href = '#main-content';
    skipLink.textContent = 'Skip to content';
    document.body.insertBefore(skipLink, document.body.firstChild);
    
    // Add ID to main content area if not present
    const mainContent = document.querySelector('main');
    if (mainContent && !mainContent.id) {
        mainContent.id = 'main-content';
    }
}

// Apply Gradient Text to Headings
function applyGradientTextToHeadings() {
    // Apply to specific headings
    const headings = document.querySelectorAll('.section h2, .hero h2');
    headings.forEach(heading => {
        heading.classList.add('gradient-text');
    });
}

// Enhance Form Elements
function enhanceFormElements() {
    // Add animated label effect to form inputs
    const formGroups = document.querySelectorAll('.form-group');
    
    formGroups.forEach(group => {
        const input = group.querySelector('input, textarea');
        const label = group.querySelector('label');
        
        if (input && label) {
            // Move label inside input wrapper
            const inputWrapper = document.createElement('div');
            inputWrapper.className = 'input-wrapper';
            input.parentNode.insertBefore(inputWrapper, input);
            inputWrapper.appendChild(input);
            inputWrapper.appendChild(label);
            
            // Add floating label class
            label.classList.add('floating-label');
            
            // Check initial state
            if (input.value) {
                label.classList.add('active');
            }
            
            // Add event listeners
            input.addEventListener('focus', () => {
                label.classList.add('active');
            });
            
            input.addEventListener('blur', () => {
                if (!input.value) {
                    label.classList.remove('active');
                }
            });
        }
    });
}

// Helper function: Debounce
function debounce(func, wait = 20, immediate = false) {
    let timeout;
    return function() {
        const context = this, args = arguments;
        const later = function() {
            timeout = null;
            if (!immediate) func.apply(context, args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func.apply(context, args);
    };
}