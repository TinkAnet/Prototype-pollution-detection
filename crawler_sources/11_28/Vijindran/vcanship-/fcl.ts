// fcl.ts
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { State, setState, resetFclState, Quote, FclDetails, ComplianceDoc, FclContainer } from './state';
import { switchPage, updateProgressBar, showToast, toggleLoading } from './ui';
import { getHsCodeSuggestions } from './api';
import { MARKUP_CONFIG } from './pricing';
import { checkAndDecrementLookup } from './api';
import { Type } from '@google/genai';
import { createQuoteCard } from './components';
import { blobToBase64 } from './utils';


// --- MODULE STATE ---
let canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D, painting = false;
let currentFclQuotes: Quote[] = [];

// --- UI RENDERING & STEP MANAGEMENT ---

function goToFclStep(step: number) {
    setState({ currentFclStep: step });
    updateProgressBar('trade-finance', step - 1); // Reusing progress bar style
    document.querySelectorAll('#page-fcl .service-step').forEach(s => s.classList.remove('active'));
    document.getElementById(`fcl-step-${step}`)?.classList.add('active');
    
    if (step === 3) {
        initializeSignaturePad();
    }
}

function renderFclPage() {
    const page = document.getElementById('page-fcl');
    if (!page) return;

    page.innerHTML = `
        <button class="back-btn">Back to Services</button>
        <div class="service-page-header">
            <h2>Book Full Container Load (FCL)</h2>
            <p class="subtitle">Secure exclusive use of a container for your large shipments.</p>
        </div>
        <div class="form-container">
             <div class="visual-progress-bar" id="progress-bar-trade-finance">
                <div class="progress-step"></div><div class="progress-step"></div><div class="progress-step"></div><div class="progress-step"></div>
            </div>

            <!-- Step 1: Details -->
            <div id="fcl-step-1" class="service-step">
                <form id="fcl-quote-form" novalidate>
                    <div class="form-section">
                        <h3>Service Type</h3>
                        <div id="fcl-service-type-selector" class="service-type-selector">
                            <button type="button" class="service-type-btn active" data-type="port-to-port"><strong>Port-to-Port</strong><span>You handle transport to/from ports.</span></button>
                            <button type="button" class="service-type-btn" data-type="door-to-port"><strong>Door-to-Port</strong><span>We pick up from your door.</span></button>
                            <button type="button" class="service-type-btn" data-type="port-to-door"><strong>Port-to-Door</strong><span>We deliver to their door.</span></button>
                            <button type="button" class="service-type-btn" data-type="door-to-door"><strong>Door-to-Door</strong><span>We handle the entire journey.</span></button>
                        </div>
                    </div>

                    <div class="form-section two-column">
                        <div id="fcl-origin-section">
                            <h4>Origin</h4>
                            <div id="fcl-pickup-address-fields" class="hidden">
                                <div class="input-wrapper"><label for="fcl-pickup-name">Sender Name/Company</label><input type="text" id="fcl-pickup-name"></div>
                                <div class="input-wrapper"><label for="fcl-pickup-country">Country</label><input type="text" id="fcl-pickup-country"></div>
                            </div>
                             <div id="fcl-pickup-location-fields">
                                <div class="input-wrapper"><label for="fcl-pickup-port">Port of Loading</label><input type="text" id="fcl-pickup-port" placeholder="e.g., Shanghai or CNSHA"></div>
                            </div>
                        </div>
                         <div id="fcl-destination-section">
                            <h4>Destination</h4>
                            <div id="fcl-delivery-address-fields" class="hidden">
                                <div class="input-wrapper"><label for="fcl-delivery-name">Recipient Name/Company</label><input type="text" id="fcl-delivery-name"></div>
                                <div class="input-wrapper"><label for="fcl-delivery-country">Country</label><input type="text" id="fcl-delivery-country"></div>
                            </div>
                            <div id="fcl-delivery-location-fields">
                                <div class="input-wrapper"><label for="fcl-delivery-port">Port of Discharge</label><input type="text" id="fcl-delivery-port" placeholder="e.g., Los Angeles or USLAX"></div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-section">
                        <h4>Cargo & Container Details</h4>
                        <div class="input-wrapper">
                            <label for="fcl-cargo-description">Cargo Description</label>
                            <textarea id="fcl-cargo-description" required placeholder="e.g., 15 pallets of consumer electronics"></textarea>
                        </div>
                         <div class="hs-code-suggester-wrapper">
                            <div class="input-wrapper">
                                <label for="fcl-hs-code">HS Code (Harmonized System)</label>
                                <div class="hs-code-input-group">
                                    <input type="text" id="fcl-hs-code" autocomplete="off" placeholder="Type description to get suggestions">
                                    <button type="button" id="fcl-hs-image-suggester-btn" class="secondary-btn hs-image-suggester-btn">
                                        <i class="fa-solid fa-camera"></i> Image
                                    </button>
                                </div>
                                <div class="hs-code-suggestions" id="fcl-hs-code-suggestions"></div>
                                <input type="file" id="fcl-hs-image-input" class="hidden" accept="image/*">
                                <p class="helper-text">This code is used by customs worldwide. Our AI can suggest one based on your description or an image.</p>
                            </div>
                        </div>
                        <div id="fcl-container-list" style="margin-top: 1.5rem;"></div>
                        <button type="button" id="fcl-add-container-btn" class="secondary-btn">Add Container</button>
                    </div>

                    <div class="form-actions">
                        <button type="submit" class="main-submit-btn">Get Quote & Compliance</button>
                    </div>
                </form>
            </div>
            
            <!-- Step 2: Quote & Compliance -->
            <div id="fcl-step-2" class="service-step">
                <h3>Quote & Compliance</h3>
                <div class="results-layout-grid">
                    <main class="results-main-content">
                        <div id="fcl-results-controls" class="results-controls"></div>
                        <div id="fcl-quotes-container"></div>
                    </main>
                    <aside id="fcl-sidebar-container" class="results-sidebar"></aside>
                </div>
                <div class="form-actions" style="justify-content: space-between;">
                    <button type="button" id="fcl-back-to-details-btn" class="secondary-btn">Back</button>
                    <button type="button" id="fcl-to-agreement-btn" class="main-submit-btn" disabled>Proceed with Selected Quote</button>
                </div>
            </div>

            <!-- Step 3: Agreement -->
            <div id="fcl-step-3" class="service-step">
                 <h3>Agreement & Finalization</h3>
                 <div class="two-column">
                    <div>
                        <h4>Booking Summary</h4>
                        <div id="fcl-agreement-summary" class="payment-overview"></div>
                        <div class="checkbox-wrapper" style="margin-top: 1.5rem;">
                            <input type="checkbox" id="fcl-compliance-ack">
                            <label for="fcl-compliance-ack">I acknowledge that providing the required compliance documents is my responsibility.</label>
                        </div>
                    </div>
                    <div>
                        <h4>Digital Signature</h4>
                        <div class="input-wrapper">
                            <label for="fcl-signer-name">Sign by Typing Your Full Name</label>
                            <input type="text" id="fcl-signer-name">
                        </div>
                        <label>Sign in the box below</label>
                        <canvas id="fcl-signature-pad" width="400" height="150" style="border: 2px solid var(--border-color); border-radius: 8px; cursor: crosshair;"></canvas>
                    </div>
                 </div>
                 <div class="form-actions" style="justify-content: space-between;">
                    <button type="button" id="fcl-back-to-compliance-btn" class="secondary-btn">Back</button>
                    <button type="button" id="fcl-to-payment-btn" class="main-submit-btn" disabled>Confirm Booking Request</button>
                </div>
            </div>

            <!-- Step 4: Confirmation -->
            <div id="fcl-step-4" class="service-step">
                <div class="confirmation-container">
                    <h3 id="fcl-confirmation-title">Booking Request Sent!</h3>
                    <p id="fcl-confirmation-message">Your FCL shipment request has been received. Our operations team will be in touch via email to coordinate the next steps.</p>
                    <div class="confirmation-tracking">
                        <h4>Reference ID</h4>
                        <div class="tracking-id-display" id="fcl-booking-id"></div>
                    </div>
                    <div class="confirmation-actions">
                         <button id="fcl-download-docs-btn" class="secondary-btn">Download Summary (PDF)</button>
                         <button id="fcl-new-shipment-btn" class="main-submit-btn">New Shipment</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// --- UI & EVENT HANDLERS ---

function handleServiceTypeChange(type: string) {
    document.querySelectorAll('#fcl-service-type-selector .service-type-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`#fcl-service-type-selector .service-type-btn[data-type="${type}"]`)?.classList.add('active');

    const showOriginAddress = type.startsWith('door-to');
    const showDestAddress = type.endsWith('-to-door');

    document.getElementById('fcl-pickup-address-fields')?.classList.toggle('hidden', !showOriginAddress);
    document.getElementById('fcl-pickup-location-fields')?.classList.toggle('hidden', showOriginAddress);
    document.getElementById('fcl-delivery-address-fields')?.classList.toggle('hidden', !showDestAddress);
    document.getElementById('fcl-delivery-location-fields')?.classList.toggle('hidden', showDestAddress);
}

function renderContainerItems() {
    const list = document.getElementById('fcl-container-list');
    if (!list) return;
    const items = State.fclDetails?.containers || [];
    list.innerHTML = items.map((item, index) => `
        <div class="card" data-index="${index}" style="margin-bottom: 1rem; padding: 1rem;">
            <div class="form-grid" style="grid-template-columns: 2fr 1fr 1fr 1fr auto; gap: 1rem; align-items: flex-end;">
                <div class="input-wrapper" style="margin-bottom: 0;"><label>Container Type</label><select class="fcl-container-type"><option ${item.type === '20GP' ? 'selected':''}>20GP</option><option ${item.type === '40GP' ? 'selected':''}>40GP</option><option ${item.type === '40HC' ? 'selected':''}>40HC</option></select></div>
                <div class="input-wrapper" style="margin-bottom: 0;"><label>Quantity</label><input type="number" class="fcl-container-quantity" value="${item.quantity}" min="1"></div>
                <div class="input-wrapper" style="margin-bottom: 0;"><label>Weight</label><input type="number" class="fcl-container-weight" value="${item.weight || ''}" min="1"></div>
                <div class="input-wrapper" style="margin-bottom: 0;"><label>Unit</label><select class="fcl-container-weight-unit"><option ${item.weightUnit === 'KG' ? 'selected':''}>KG</option><option ${item.weightUnit === 'TON' ? 'selected':''}>TON</option></select></div>
                <button type="button" class="secondary-btn fcl-remove-container-btn">&times;</button>
            </div>
        </div>
    `).join('');
}

function updateContainersFromUI() {
    const containers: FclContainer[] = [];
    document.querySelectorAll('#fcl-container-list .card').forEach(el => {
        containers.push({
            type: (el.querySelector('.fcl-container-type') as HTMLSelectElement).value,
            quantity: parseInt((el.querySelector('.fcl-container-quantity') as HTMLInputElement).value) || 1,
            weight: parseInt((el.querySelector('.fcl-container-weight') as HTMLInputElement).value) || 0,
            weightUnit: (el.querySelector('.fcl-container-weight-unit') as HTMLSelectElement).value as 'KG' | 'TON',
        });
    });
    setState({ fclDetails: { ...State.fclDetails, containers } as FclDetails });
}

function initializeSignaturePad() {
    canvas = document.getElementById('fcl-signature-pad') as HTMLCanvasElement;
    if (!canvas) return;
    ctx = canvas.getContext('2d')!;
    ctx.strokeStyle = '#212121'; ctx.lineWidth = 2;

    const start = (e: MouseEvent | TouchEvent) => { painting = true; draw(e); };
    const end = () => { painting = false; ctx.beginPath(); setState({ fclSignatureDataUrl: canvas.toDataURL() }); validateAgreement(); };
    const draw = (e: MouseEvent | TouchEvent) => {
        if (!painting) return;
        e.preventDefault();
        const rect = canvas.getBoundingClientRect();
        const pos = e instanceof MouseEvent ? e : e.touches[0];
        ctx.lineTo(pos.clientX - rect.left, pos.clientY - rect.top);
        ctx.stroke(); ctx.beginPath(); ctx.moveTo(pos.clientX - rect.left, pos.clientY - rect.top);
    };
    canvas.addEventListener('mousedown', start);
    canvas.addEventListener('mouseup', end);
    canvas.addEventListener('mousemove', draw);
    canvas.addEventListener('touchstart', start);
    canvas.addEventListener('touchend', end);
    canvas.addEventListener('touchmove', draw);
}

function validateAgreement() {
    const ack = (document.getElementById('fcl-compliance-ack') as HTMLInputElement).checked;
    const name = (document.getElementById('fcl-signer-name') as HTMLInputElement).value.trim();
    const isSigned = !!State.fclSignatureDataUrl;
    (document.getElementById('fcl-to-payment-btn') as HTMLButtonElement).disabled = !(ack && name && isSigned);
}

async function handleFclFormSubmit(e: Event) {
    e.preventDefault();
    updateContainersFromUI();
    
    if (!checkAndDecrementLookup()) return;

    toggleLoading(true, "Analyzing your FCL shipment...");

    const serviceType = document.querySelector('#fcl-service-type-selector .service-type-btn.active')?.getAttribute('data-type') || 'port-to-port';
    const pickupAddress = serviceType.startsWith('door-to') ? {
        name: (document.getElementById('fcl-pickup-name') as HTMLInputElement).value,
        country: (document.getElementById('fcl-pickup-country') as HTMLInputElement).value,
    } : null;
    const pickupPort = serviceType.startsWith('door-to') ? null : (document.getElementById('fcl-pickup-port') as HTMLInputElement).value;
    const deliveryAddress = serviceType.endsWith('-to-door') ? {
        name: (document.getElementById('fcl-delivery-name') as HTMLInputElement).value,
        country: (document.getElementById('fcl-delivery-country') as HTMLInputElement).value,
    } : null;
    const deliveryPort = serviceType.endsWith('-to-door') ? null : (document.getElementById('fcl-delivery-port') as HTMLInputElement).value;
    const cargoDescription = (document.getElementById('fcl-cargo-description') as HTMLTextAreaElement).value;
    const hsCode = (document.getElementById('fcl-hs-code') as HTMLInputElement).value;


    const details: FclDetails = {
        serviceType: serviceType as FclDetails['serviceType'],
        pickupType: serviceType.startsWith('door-to') ? 'address' : 'location',
        deliveryType: serviceType.endsWith('-to-door') ? 'address' : 'location',
        pickupAddress,
        deliveryAddress,
        pickupPort,
        deliveryPort,
        cargoDescription,
        hsCode,
        containers: State.fclDetails?.containers || [],
    };
    setState({ fclDetails: details });

    try {
        if (!State.api) throw new Error("API not initialized");
        const containerSummary = details.containers.map(c => `${c.quantity} x ${c.type}`).join(', ');
        const prompt = `Act as a logistics pricing expert for FCL sea freight. Provide a JSON response containing realistic quotes from 3 different carriers (e.g., Maersk, MSC, CMA CGM) and a compliance checklist.
        - Route: From ${pickupPort || pickupAddress?.country} to ${deliveryPort || deliveryAddress?.country}.
        - Containers: ${containerSummary}.
        - Cargo: ${details.cargoDescription}.
        - HS Code: ${hsCode || 'Not Provided'}.
        - Currency: ${State.currentCurrency.code}.
        
        The response should be a JSON object with two keys: "quotes" and "complianceReport".
        The "quotes" key should be an array of objects. For each quote object, provide carrierName, estimatedTransitTime, and totalCost. Apply a ${MARKUP_CONFIG.fcl.standard * 100}% markup to a realistic base cost to calculate the totalCost.
        The "complianceReport" should have status, summary, and a list of requirements (each with title and description, e.g., Commercial Invoice, Packing List).
        Your response MUST be a single JSON object matching the provided schema. Do not include any text outside the JSON.`;
        
        const responseSchema = {
            type: Type.OBJECT,
            properties: {
                quotes: {
                    type: Type.ARRAY,
                    items: {
                        type: Type.OBJECT,
                        properties: {
                            carrierName: { type: Type.STRING },
                            estimatedTransitTime: { type: Type.STRING },
                            totalCost: { type: Type.NUMBER }
                        }
                    }
                },
                complianceReport: {
                    type: Type.OBJECT,
                    properties: {
                        status: { type: Type.STRING },
                        summary: { type: Type.STRING },
                        requirements: {
                            type: Type.ARRAY,
                            items: {
                                type: Type.OBJECT,
                                properties: {
                                    title: { type: Type.STRING },
                                    description: { type: Type.STRING }
                                }
                            }
                        }
                    }
                }
            }
        };

        const result = await State.api.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: responseSchema
            }
        });

        const parsedResult = JSON.parse(result.text);

        const quotesWithBreakdown: Quote[] = parsedResult.quotes.map((q: any) => ({
            ...q,
            carrierType: "Ocean Carrier",
            chargeableWeight: 0,
            chargeableWeightUnit: 'N/A',
            weightBasis: 'Per Container',
            isSpecialOffer: Math.random() < 0.2, // 20% chance of being a special offer
            costBreakdown: {
                baseShippingCost: q.totalCost / (1 + MARKUP_CONFIG.fcl.standard),
                fuelSurcharge: 0,
                estimatedCustomsAndTaxes: 0,
                optionalInsuranceCost: 0,
                ourServiceFee: q.totalCost - (q.totalCost / (1 + MARKUP_CONFIG.fcl.standard))
            },
            serviceProvider: 'Vcanship AI'
        }));

        const docs: ComplianceDoc[] = parsedResult.complianceReport.requirements.map((r: any) => ({ ...r, id: `doc-${r.title.replace(/\s/g, '-')}`, status: 'pending', file: null, required: true }));
        
        currentFclQuotes = quotesWithBreakdown;
        setState({ fclComplianceDocs: docs });
        renderFclResultsStep(parsedResult.complianceReport);
        goToFclStep(2);
    } catch (error) {
        console.error("FCL quote error:", error);
        showToast("Could not generate an estimate. Please try again.", "error");
    } finally {
        toggleLoading(false);
    }
}

function renderFclResultsStep(complianceReport: any) {
    const sidebarContainer = document.getElementById('fcl-sidebar-container');
    const controlsContainer = document.getElementById('fcl-results-controls');
    const quotesContainer = document.getElementById('fcl-quotes-container');

    if (sidebarContainer) {
        sidebarContainer.innerHTML = `
             <div class="results-section">
                <h3><i class="fa-solid fa-file-shield"></i> Compliance Report</h3>
                <div class="compliance-report">
                    <p>${complianceReport.summary}</p>
                    <ul>${complianceReport.requirements.map((req: any) => `<li><strong>${req.title}</strong></li>`).join('')}</ul>
                </div>
             </div>
             <div class="quote-confirmation-panel">
                <h4>This is an AI Estimate</h4>
                <p>A Vcanship agent will contact you to confirm the final details and provide an exact quote for your approval before booking.</p>
            </div>
        `;
    }

    if (controlsContainer) {
         controlsContainer.innerHTML = `
            <h3>Sort By:</h3>
            <div class="sort-buttons">
                <button class="sort-btn active" data-sort="price">Cheapest First</button>
                <button class="sort-btn" data-sort="speed">Fastest First</button>
            </div>
        `;
    }
    
    if (quotesContainer) {
        if (!currentFclQuotes || currentFclQuotes.length === 0) {
            quotesContainer.innerHTML = '<p class="helper-text">No quotes could be generated for this route.</p>';
            return;
        }
        sortAndRenderFclQuotes('price');
    }
}

function sortAndRenderFclQuotes(sortBy: 'price' | 'speed') {
    const quotesContainer = document.getElementById('fcl-quotes-container');
    if (!quotesContainer) return;

    const sortedQuotes = [...currentFclQuotes];
    const parseTransit = (time: string) => parseInt(time.split('-')[0]);

    if (sortBy === 'price') {
        sortedQuotes.sort((a, b) => a.totalCost - b.totalCost);
    } else {
        sortedQuotes.sort((a, b) => parseTransit(a.estimatedTransitTime) - parseTransit(b.estimatedTransitTime));
    }
    
    quotesContainer.innerHTML = sortedQuotes.map(q => createQuoteCard(q)).join('');

    document.querySelectorAll('#fcl-results-controls .sort-btn').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-sort') === sortBy);
    });
}

async function suggestHsCodeFromImage(file: File, inputElementId: string) {
    if (!State.api) { showToast("AI not initialized.", "error"); return; }
    toggleLoading(true, "Analyzing image for HS code...");
    try {
        const base64Data = await blobToBase64(file);
        const imagePart = { inlineData: { mimeType: file.type, data: base64Data } };
        const textPart = { text: "Analyze this image of a product and suggest the most appropriate 6-digit Harmonized System (HS) code. Provide only the 6-digit code as a string." };
        
        const result = await State.api.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: { parts: [imagePart, textPart] }
        });

        const hsCode = result.text.replace(/[^0-9]/g, '').slice(0, 6);
        if (hsCode.length === 6) {
            const inputEl = document.getElementById(inputElementId) as HTMLInputElement;
            if(inputEl) inputEl.value = hsCode;
            showToast(`AI suggested HS Code: ${hsCode}`, "success");
        } else {
            throw new Error("Could not extract a valid HS code from the image.");
        }
    } catch (error) {
        console.error("HS code from image error:", error);
        showToast("Could not determine HS code from image.", "error");
    } finally {
        toggleLoading(false);
    }
}

function attachFclEventListeners() {
    const page = document.getElementById('page-fcl');
    if (!page) return;

    page.querySelector('.back-btn')?.addEventListener('click', () => switchPage('landing'));
    document.getElementById('fcl-quote-form')?.addEventListener('submit', handleFclFormSubmit);

    page.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        const serviceTypeBtn = target.closest<HTMLButtonElement>('.service-type-btn');
        if (serviceTypeBtn?.dataset.type) {
            handleServiceTypeChange(serviceTypeBtn.dataset.type);
        }
        
        if (target.closest('.fcl-remove-container-btn')) {
            const index = parseInt(target.closest<HTMLElement>('.card')?.dataset.index || '-1');
            if (index > -1 && State.fclDetails?.containers) {
                const newContainers = State.fclDetails.containers.filter((_, i) => i !== index);
                setState({ fclDetails: { ...State.fclDetails, containers: newContainers } as FclDetails });
                renderContainerItems();
            }
        }

        if (target.closest('.sort-btn')) {
            sortAndRenderFclQuotes(target.dataset.sort as 'price' | 'speed');
        }
        
        const selectBtn = target.closest<HTMLButtonElement>('.select-quote-btn');
        if (selectBtn?.dataset.quote) {
            const quote: Quote = JSON.parse(selectBtn.dataset.quote.replace(/&quot;/g, '"'));
            setState({ fclQuote: quote });
            document.querySelectorAll('#fcl-quotes-container .quote-card').forEach(c => c.classList.remove('selected'));
            selectBtn.closest('.quote-card')?.classList.add('selected');
            (document.getElementById('fcl-to-agreement-btn') as HTMLButtonElement).disabled = false;
        }
        if (target.closest('#fcl-hs-image-suggester-btn')) {
            document.getElementById('fcl-hs-image-input')?.click();
        }
    });

    document.getElementById('fcl-add-container-btn')?.addEventListener('click', addContainerItem);

    // HS Code Suggesters
    const hsImageInput = document.getElementById('fcl-hs-image-input') as HTMLInputElement;
    hsImageInput?.addEventListener('change', () => {
        const file = hsImageInput.files?.[0];
        if (file) {
            suggestHsCodeFromImage(file, 'fcl-hs-code');
        }
    });
    
    // Navigation buttons
    document.getElementById('fcl-back-to-details-btn')?.addEventListener('click', () => goToFclStep(1));
    document.getElementById('fcl-to-agreement-btn')?.addEventListener('click', () => {
        const summaryEl = document.getElementById('fcl-agreement-summary');
        if (summaryEl && State.fclQuote) {
            summaryEl.innerHTML = `
                <div class="review-item"><span>Carrier:</span><strong>${State.fclQuote.carrierName}</strong></div>
                <div class="review-item"><span>Transit Time:</span><strong>~${State.fclQuote.estimatedTransitTime}</strong></div>
                <hr>
                <div class="review-item total"><span>Est. Total Cost:</span><strong>${State.currentCurrency.symbol}${State.fclQuote.totalCost.toFixed(2)}</strong></div>
            `;
        }
        goToFclStep(3);
    });
    document.getElementById('fcl-back-to-compliance-btn')?.addEventListener('click', () => goToFclStep(2));
    document.getElementById('fcl-to-payment-btn')?.addEventListener('click', () => {
        const bookingId = `FCL-${Date.now().toString().slice(-6)}`;
        setState({ fclBookingId: bookingId });
        (document.getElementById('fcl-booking-id') as HTMLElement).textContent = bookingId;
        goToFclStep(4);
    });
    document.getElementById('fcl-new-shipment-btn')?.addEventListener('click', () => startFcl());
    
    // Agreement validation
    document.getElementById('fcl-compliance-ack')?.addEventListener('change', validateAgreement);
    document.getElementById('fcl-signer-name')?.addEventListener('input', validateAgreement);
}

function addContainerItem() {
    const currentContainers = State.fclDetails?.containers || [];
    const newContainers: FclContainer[] = [...currentContainers, { type: '20GP', quantity: 1, weight: 0, weightUnit: 'KG' as const }];
    setState({ fclDetails: { ...State.fclDetails, containers: newContainers } as FclDetails });
    renderContainerItems();
}

// --- INITIALIZATION ---
export function startFcl() {
    setState({ currentService: 'fcl' });
    resetFclState();
    renderFclPage();
    switchPage('fcl');
    attachFclEventListeners();
    goToFclStep(1);
    addContainerItem(); // Start with one container
    handleServiceTypeChange('port-to-port'); // Set initial default
}