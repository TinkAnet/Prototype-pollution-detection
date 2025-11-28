// ⚠️  READ-ONLY — DO NOT EDIT — SERVICE LOCKED ⚠️
import { jsPDF } from 'jspdf';
import { State, setState, type Quote, type Address, resetParcelState, type DropOffLocation, ApiResponse } from './state';
import { getHsCodeSuggestions, checkAndDecrementLookup } from './api';
import { showToast, switchPage, toggleLoading } from './ui';
import { DOMElements } from './dom';
import { t } from './i18n';
import { attachDynamicPostcodeValidation } from './validation';
import { MARKUP_CONFIG } from './pricing';
import { Type } from '@google/genai';
import { firebaseConfig } from './firebase';

let allQuotes: Quote[] = [];
let carriers: string[] = [];
let currentView: 'form' | 'results' | 'payment' | 'confirmation' = 'form';

// --- VIEW RENDERING ---

function renderCurrentView() {
    const page = document.getElementById('page-parcel');
    if (!page) return;

    // Use a simple transition
    page.style.opacity = '0';
    setTimeout(() => {
        switch (currentView) {
            case 'form':
                page.innerHTML = renderFormView();
                attachFormListeners();
                break;
            case 'results':
                page.innerHTML = renderResultsView(allQuotes);
                attachResultsListeners();
                break;
             case 'payment':
                page.innerHTML = renderPaymentView();
                attachPaymentListeners();
                break;
            case 'confirmation':
                page.innerHTML = renderConfirmationView();
                attachConfirmationListeners();
                break;
        }
        page.style.opacity = '1';
    }, 200);
}

function renderFormView(): string {
    return `
        <button class="back-btn static-link" data-page="landing"><i class="fa-solid fa-arrow-left"></i> Back to Services</button>
        <div class="service-page-header" style="margin-bottom: 2rem;">
            <h2>Send a Parcel</h2>
            <p class="subtitle">Enter your shipment details to get a quote.</p>
        </div>
        <div class="parcel-form-layout">
            <div class="parcel-form-main">
                <form id="parcel-details-form" novalidate>
                    <div class="input-wrapper"><label for="origin-postcode">From</label><input type="text" id="origin-postcode" placeholder="Origin Country/Postcode" required></div>
                    <div class="input-wrapper"><label for="destination-postcode">To</label><input type="text" id="destination-postcode" placeholder="Destination Country/Postcode" required></div>
                    <div class="input-wrapper"><label for="package-weight">Weight (kg)</label><input type="number" id="package-weight" placeholder="e.g., 2" required min="0.1" step="0.1"></div>
                    <div class="form-actions" style="margin-top: 2rem;">
                        <button type="submit" class="main-submit-btn">Get a Quote</button>
                    </div>
                </form>
            </div>
            <aside class="parcel-form-sidebar">
                <h3>Find a Drop-off Point</h3>
                <p class="helper-text" style="margin-bottom: 1rem;">Enter your postcode to find nearby parcel drop-off locations.</p>
                <form id="parcel-dropoff-search-form">
                    <div class="input-wrapper">
                        <label for="postcode-search">Your Postcode</label>
                        <input type="text" id="postcode-search" placeholder="Enter postcode...">
                    </div>
                    <div class="form-actions" style="margin-top: 1rem; justify-content: flex-start;">
                        <button type="submit" class="secondary-btn">
                            <i class="fa-solid fa-magnifying-glass-location"></i> Search Locations
                        </button>
                    </div>
                </form>
            </aside>
        </div>
    `;
}


function renderResultsView(quotes: Quote[]): string {
    carriers = [...new Set(quotes.map(q => q.carrierName))];
    return `
        <button class="back-btn" id="parcel-back-to-form-btn"><i class="fa-solid fa-arrow-left"></i> Back to Details</button>
        <div class="parcel-results-layout">
            <aside id="parcel-filters-sidebar" class="parcel-filters-sidebar">
                <div class="card" style="border-width: 1px;">
                    <div class="filter-group">
                        <h4>Filter Results</h4>
                        <div class="service-toggle-group">
                            <button class="service-toggle-btn active" data-filter="service" value="all">All</button>
                            <button class="service-toggle-btn" data-filter="service" value="Drop-off">Drop-off</button>
                            <button class="service-toggle-btn" data-filter="service" value="Collection">Collection</button>
                        </div>
                    </div>
                    <div class="filter-group">
                        <h4>Couriers</h4>
                        ${carriers.map(c => `<div class="checkbox-wrapper"><input type="checkbox" id="courier-${c.toLowerCase().replace(/\s/g, '')}" data-filter="courier" value="${c}" checked><label for="courier-${c.toLowerCase().replace(/\s/g, '')}">${c}</label></div>`).join('')}
                    </div>
                </div>
            </aside>
            <main id="parcel-quotes-container" class="parcel-quotes-main"></main>
        </div>
    `;
}

function renderPaymentView(): string {
     const quote = State.parcelSelectedQuote;
     if(!quote) return 'Error: No quote selected.';
    return `
        <button class="back-btn" id="parcel-back-to-results-btn"><i class="fa-solid fa-arrow-left"></i> Back to Quotes</button>
        <div class="form-container">
             <h3>Payment Summary</h3>
             <div class="card">
                <div class="payment-overview">
                    <div class="review-item"><span>Carrier:</span><strong>${quote.carrierName}</strong></div>
                    <div class="review-item"><span>Service:</span><strong>${quote.carrierType}</strong></div>
                    <hr>
                    <div class="review-item total"><span>Total Cost:</span><strong>${State.currentCurrency.symbol}${quote.totalCost.toFixed(2)}</strong></div>
                </div>
                <p class="helper-text" style="text-align: center; margin-top: 1.5rem;">This is a simulated payment step.</p>
            </div>
            <div class="form-actions" style="margin-top: 2rem;">
                <button id="parcel-confirm-payment-btn" class="main-submit-btn">Confirm & Pay</button>
            </div>
        </div>
    `;
}

function renderConfirmationView(): string {
    const trackingId = `PAR-${Date.now().toString().slice(-7)}`;
    return `
        <div class="confirmation-container">
            <h3 id="parcel-confirmation-title">
                <div class="confirmation-icon-wrapper">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" /></svg>
                </div>
                <span>Shipment Confirmed!</span>
            </h3>
            <p>Your parcel has been booked. Details have been sent to your email.</p>
            <div class="confirmation-tracking">
                <h4>Your Tracking ID</h4>
                <div class="tracking-id-display">${trackingId}</div>
            </div>
            <div class="confirmation-actions">
                 <button id="parcel-new-shipment-btn" class="main-submit-btn">New Shipment</button>
            </div>
        </div>
    `;
}

// --- LOGIC AND EVENT HANDLERS ---

async function handleFormSubmit(e: Event) {
    e.preventDefault();
    if (!checkAndDecrementLookup()) return;
    
    toggleLoading(true, "Finding best quotes...");

    const origin = (document.getElementById('origin-postcode') as HTMLInputElement).value;
    const destination = (document.getElementById('destination-postcode') as HTMLInputElement).value;
    const weight = parseFloat((document.getElementById('package-weight') as HTMLInputElement).value);
    
    setState({ parcelOrigin: { postcode: origin }, parcelDestination: { postcode: destination }, parcelInitialWeight: weight });

    try {
        if (!State.api) throw new Error("API not initialized");
        const prompt = `Act as a logistics pricing API. Based on the following parcel shipment, provide a JSON response containing realistic quotes from 4-5 different carriers (like DHL, UPS, FedEx, DPD, Evri). Origin: ${origin}. Destination: ${destination}. Weight: ${weight} kg. Currency: ${State.currentCurrency.code}. For each quote, provide: carrierName, carrierType (e.g., Express Drop-off), totalCost, estimatedTransitTime (e.g., "1-2 working days"), serviceProvider ('Vcanship AI'), and a boolean 'isSpecialOffer'. Your response MUST be a single JSON object with a "quotes" key, which is an array of quote objects.`;
        
        const responseSchema = { type: Type.OBJECT, properties: { quotes: { type: Type.ARRAY, items: { type: Type.OBJECT, properties: { carrierName: { type: Type.STRING }, carrierType: { type: Type.STRING }, totalCost: { type: Type.NUMBER }, estimatedTransitTime: { type: Type.STRING }, serviceProvider: { type: Type.STRING }, isSpecialOffer: { type: Type.BOOLEAN } } } } } };

        const result = await State.api.models.generateContent({ model: 'gemini-2.5-flash', contents: prompt, config: { responseMimeType: 'application/json', responseSchema } });
        const response: { quotes: Quote[] } = JSON.parse(result.text);

        allQuotes = response.quotes.map(q => ({ ...q, chargeableWeight: weight, chargeableWeightUnit: 'kg' }));
        
        currentView = 'results';
        renderCurrentView();

    } catch (error) {
        console.error('Error getting quotes:', error);
        showToast("Sorry, we couldn't fetch quotes at this time.", "error");
    } finally {
        toggleLoading(false);
    }
}

function applyAndRenderFilteredQuotes() {
    const quotesContainer = document.getElementById('parcel-quotes-container');
    if (!quotesContainer) return;
    
    const serviceFilter = (document.querySelector('.service-toggle-btn.active') as HTMLElement)?.dataset.value || 'all';
    const selectedCouriers = Array.from(document.querySelectorAll<HTMLInputElement>('input[data-filter="courier"]:checked')).map(cb => cb.value);

    const filteredQuotes = allQuotes.filter(q => {
        const serviceMatch = serviceFilter === 'all' || q.carrierType.toLowerCase().includes(serviceFilter.toLowerCase());
        const courierMatch = selectedCouriers.includes(q.carrierName);
        return serviceMatch && courierMatch;
    });

    if (filteredQuotes.length === 0) {
        quotesContainer.innerHTML = `<p class="helper-text">No services match your criteria. Try adjusting the filters.</p>`;
        return;
    }

    quotesContainer.innerHTML = filteredQuotes.map(createDetailedQuoteCard).join('');
}

function createDetailedQuoteCard(quote: Quote): string {
    const safeQuoteData = JSON.stringify(quote).replace(/"/g, '&quot;');
    return `
        <div class="card p2g-quote-card" data-carrier="${quote.carrierName}">
            <div class="p2g-quote-header">
                <img src="https://logo.clearbit.com/${quote.carrierName.toLowerCase().replace(/\s/g, '')}.com?size=80" alt="${quote.carrierName}" class="carrier-logo">
                <div class="p2g-quote-info">
                    <h4>${quote.carrierName}</h4>
                    <p>${quote.carrierType}</p>
                </div>
            </div>
            <div class="p2g-quote-price">
                <span class="price-display">${State.currentCurrency.symbol}${quote.totalCost.toFixed(2)}</span>
                <button class="main-submit-btn select-quote-btn" data-quote="${safeQuoteData}">Select & Proceed</button>
            </div>
            <div class="p2g-quote-features">
                <div class="feature-item"><i class="fa-solid fa-clock"></i><span>${quote.estimatedTransitTime}</span></div>
            </div>
        </div>
    `;
}

// NEW: Function to handle finding and displaying drop-off locations
async function findDropoffLocations(postcode: string) {
    const modal = document.getElementById('dropoff-locations-modal');
    const closeBtn = document.getElementById('close-dropoff-modal-btn');
    const listContainer = document.getElementById('dropoff-locations-list');
    const loadingContainer = modal?.querySelector('.loading-spinner-container') as HTMLElement;
    const descEl = document.getElementById('dropoff-modal-desc');

    if (!modal || !closeBtn || !listContainer || !loadingContainer || !descEl) {
        console.error('Dropoff modal elements not found.');
        return;
    }
    
    // Show modal and loading state
    modal.classList.add('active');
    listContainer.innerHTML = '';
    loadingContainer.style.display = 'flex';
    descEl.textContent = `Searching for locations near ${postcode}...`;

    const closeModal = () => modal.classList.remove('active');
    closeBtn.onclick = closeModal;

    if (!State.api) {
        showToast("AI service is not available.", "error");
        loadingContainer.style.display = 'none';
        listContainer.innerHTML = '<li class="helper-text" style="padding: 1rem;">Could not connect to service.</li>';
        return;
    }
    if (!checkAndDecrementLookup()) {
        closeModal();
        return;
    }

    try {
        const position = await new Promise<GeolocationPosition>((resolve, reject) => {
            navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 5000 });
        });
        
        const prompt = `Find up to 10 parcel drop-off locations (like post offices, courier points, or convenience stores with parcel services) near ${postcode}.`;

        const response = await State.api.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt,
            config: {
                tools: [{ googleMaps: {} }],
                responseMimeType: "application/json",
                responseSchema: {
                    type: Type.OBJECT,
                    properties: {
                        locations: {
                            type: Type.ARRAY,
                            description: 'A list of nearby parcel drop-off locations.',
                            items: {
                                type: Type.OBJECT,
                                properties: {
                                    name: { type: Type.STRING, description: 'The name of the location.' },
                                    address: { type: Type.STRING, description: 'The full street address of the location.' }
                                }
                            }
                        }
                    }
                },
                toolConfig: {
                    retrievalConfig: {
                        latLng: {
                            latitude: position.coords.latitude,
                            longitude: position.coords.longitude
                        }
                    }
                }
            },
        });

        const result = JSON.parse(response.text);
        const locations = result.locations || [];
        
        loadingContainer.style.display = 'none';
        
        if (locations.length > 0) {
            descEl.textContent = `Select a location to get directions.`;
            listContainer.innerHTML = locations.map((loc: { name: string, address: string }) => `
                <li class="dropoff-location-item" data-address="${encodeURIComponent(loc.address)}">
                    <div class="location-icon"><i class="fa-solid fa-location-dot"></i></div>
                    <div class="location-info">
                        <strong>${loc.name}</strong>
                        <span>${loc.address}</span>
                    </div>
                </li>
            `).join('');
            
            listContainer.querySelectorAll('.dropoff-location-item').forEach(item => {
                item.addEventListener('click', () => {
                    const address = (item as HTMLElement).dataset.address;
                    if (address) {
                        const url = `https://www.google.com/maps/dir/?api=1&destination=${address}`;
                        window.open(url, '_blank');
                        closeModal();
                    }
                });
            });
        } else {
            descEl.textContent = `No locations found.`;
            listContainer.innerHTML = '<li class="helper-text" style="padding: 1rem;">We couldn\'t find any drop-off locations for that area. Please try a different postcode.</li>';
        }

    } catch (error: any) {
        console.error("Error finding drop-off locations:", error);
        loadingContainer.style.display = 'none';
        listContainer.innerHTML = '<li class="helper-text" style="padding: 1rem;">Sorry, there was an error finding locations. Please try again.</li>';
        if (error.code === 1) { // Geolocation permission denied
            showToast("Please allow location access to find nearby drop-off points.", "warning");
            descEl.textContent = "Location access is required for this feature.";
        } else {
            showToast("An error occurred while searching for locations.", "error");
        }
    }
}


// --- EVENT LISTENER ATTACHMENT ---

function attachFormListeners() {
    document.getElementById('parcel-details-form')?.addEventListener('submit', handleFormSubmit);

    // MODIFIED: listener for drop-off search
    const dropoffForm = document.getElementById('parcel-dropoff-search-form');
    dropoffForm?.addEventListener('submit', (e) => {
        e.preventDefault();
        const postcode = (document.getElementById('postcode-search') as HTMLInputElement).value;
        if (postcode.trim()) {
            findDropoffLocations(postcode.trim());
        } else {
            showToast('Please enter a postcode to search.', 'warning');
        }
    });
}

function attachResultsListeners() {
    document.getElementById('parcel-back-to-form-btn')?.addEventListener('click', () => {
        currentView = 'form';
        renderCurrentView();
    });

    const filtersSidebar = document.getElementById('parcel-filters-sidebar');
    filtersSidebar?.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        if (target.matches('.service-toggle-btn')) {
            filtersSidebar.querySelectorAll('.service-toggle-btn').forEach(btn => btn.classList.remove('active'));
            target.classList.add('active');
            applyAndRenderFilteredQuotes();
        }
    });
    filtersSidebar?.addEventListener('change', (e) => {
        if ((e.target as HTMLInputElement).matches('input[data-filter="courier"]')) {
            applyAndRenderFilteredQuotes();
        }
     });

    document.getElementById('parcel-quotes-container')?.addEventListener('click', e => {
        const target = e.target as HTMLElement;
        const selectBtn = target.closest<HTMLButtonElement>('.select-quote-btn');
        if (selectBtn?.dataset.quote) {
             const quote: Quote = JSON.parse(selectBtn.dataset.quote.replace(/&quot;/g, '"'));
             setState({ parcelSelectedQuote: quote });
             currentView = 'payment';
             renderCurrentView();
        }
    });

    // Initial render of quotes
    applyAndRenderFilteredQuotes();
}

function attachPaymentListeners() {
    document.getElementById('parcel-back-to-results-btn')?.addEventListener('click', () => {
        currentView = 'results';
        renderCurrentView();
    });
     document.getElementById('parcel-confirm-payment-btn')?.addEventListener('click', () => {
        currentView = 'confirmation';
        renderCurrentView();
    });
}

function attachConfirmationListeners() {
     document.getElementById('parcel-new-shipment-btn')?.addEventListener('click', () => {
        resetParcelState();
        startParcel();
     });
}

// --- INITIALIZATION ---
export function startParcel() {
    setState({ currentService: 'parcel' });
    resetParcelState();
    switchPage('parcel');
    currentView = 'form';
    renderCurrentView();
}