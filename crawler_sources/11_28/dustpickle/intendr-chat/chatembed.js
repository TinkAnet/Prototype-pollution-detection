// Chat Widget Script - Version 1.9.2

// ===== CONFIGURATION SYSTEM =====
// Default configuration - can be overridden by client-specific files
const DEFAULT_CONFIG = {
  endpoints: {
    voiceCall: 'https://automation.cloudcovehosting.com/webhook/voice-call',
    ipify: 'https://api.ipify.org?format=json'
  },
  storageKeys: {
    chatSession: 'intendrChatSession',
    chatState: 'intendrChatState',
    navLinks: 'intendr_nav_links',
    overtakeShown: 'intendrOvertakeShown'
  },
  settings: {
    version: "2.0",
    sessionValidity: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
    inactivityTimeout: 120000, // 2 minutes
    promptBubbleTimeout: 120000, // 2 minutes
    utmCampaign: 'Intendr-AIChat'
  },
  branding: {
    name: 'Intendr : AI Assistant',
    typingText: 'Intendr is typing',
    greetingText: 'Hi I am Intendr!'
  },
  hooks: {
    beforeSendMessage: null,
    afterReceiveMessage: null,
    beforePhoneCall: null,
    afterPhoneCall: null,
    customMessageProcessing: null
  }
};

// Merge with client-specific configuration if it exists
const CLIENT_CONFIG = window.ChatWidgetCustomConfig || {};
const MERGED_CONFIG = deepMerge(DEFAULT_CONFIG, CLIENT_CONFIG);

// Extract merged configuration for backward compatibility
const INTENDR_API_ENDPOINTS = MERGED_CONFIG.endpoints;
const INTENDR_STORAGE_KEYS = MERGED_CONFIG.storageKeys;
const INTENDR_SETTINGS = MERGED_CONFIG.settings;
const INTENDR_BRANDING = MERGED_CONFIG.branding;
const INTENDR_HOOKS = MERGED_CONFIG.hooks;

// Expose merged config globally for debugging and client access
window.MERGED_CONFIG = MERGED_CONFIG;

// Deep merge utility function
function deepMerge(target, source) {
  const result = { ...target };
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

// Simple phone call tracking
window.IntendrPhoneCallActive = false;

  // Load tracking pixel immediately for visitor tracking
  (function() {
    // Extract chatbot ID immediately from config
    function getChatbotIdFromConfig() {
      if (!window.ChatWidgetConfig?.webhook?.url) {
        console.warn('No webhook URL found in ChatWidgetConfig');
        return null;
      }
      
      try {
        const webhookUrl = window.ChatWidgetConfig.webhook.url;
        const matches = webhookUrl.match(/\/webhook\/([^\/]+)/);
        if (matches && matches[1]) {
          return matches[1].replace(/\/chat$/, '');
        }
      } catch (err) {
        console.error('Error extracting chatbot ID for tracking pixel:', err);
      }
      return null;
    }
    
    const chatbotId = getChatbotIdFromConfig();
    
    if (chatbotId && !window.IntendrTrackingInitialized) {
      console.log('🎯 [Tracking Pixel] Loading tracking pixel immediately for chatbot:', chatbotId);
      
      // Create script element for tracking pixel
      const trackingScript = document.createElement('script');
      trackingScript.src = 'https://intendr.ai/api/tracking-pixel';
      trackingScript.setAttribute('data-chatbot-id', chatbotId);
      trackingScript.async = true;
      trackingScript.defer = true;
      
      // Add error handling
      trackingScript.onerror = function() {
        console.warn('🚨 [Tracking Pixel] Failed to load tracking pixel script');
      };
      
      trackingScript.onload = function() {
        console.log('✅ [Tracking Pixel] Tracking pixel loaded immediately and tracking visitors');
      };
      
      // Add to document head
      document.head.appendChild(trackingScript);
    }
  })();

  // Main chat widget code
  (function() {
    // Configuration
    const CHAT_VERSION = "2.0";
    console.log("ChatVersion:", CHAT_VERSION);
    
    // Store user IP globally
    let userIP = '';
    
    // Fetch user IP address
    async function fetchUserIP() {
      try {
        const response = await fetch(INTENDR_API_ENDPOINTS.ipify);
        const data = await response.json();
        userIP = data.ip;
        console.log('User IP collected for chat');
      } catch (error) {
        console.error('Error fetching IP:', error);
        userIP = 'unknown';
      }
    }
    
    // Call IP fetch on initialization
    fetchUserIP();
    
    // Default configuration
    const defaultConfig = {
      webhook: { url: '', route: '' },
      branding: { 
        logo: 'https://cdn-icons-png.flaticon.com/512/5962/5962463.png', 
        name: 'Intendr : AI Assistant', 
        welcomeText: '' 
      },
      style: { 
        primaryColor: '#003f72', 
        secondaryColor: '#003f72', 
        position: 'right',
        backgroundColor: '#ffffff',
        fontColor: '#333333'
      },
      business: { name: '', phone: '', website: '', searchPage: '', provider: '' },
      overtake: false,
      initialButtons: []
    };
    
    // Merge user config with defaults
    const config = window.ChatWidgetConfig ? {
      webhook: { ...defaultConfig.webhook, ...window.ChatWidgetConfig.webhook },
      branding: { ...defaultConfig.branding, ...window.ChatWidgetConfig.branding },
      style: { ...defaultConfig.style, ...window.ChatWidgetConfig.style },
      business: { ...defaultConfig.business, ...window.ChatWidgetConfig.business },
      overtake: window.ChatWidgetConfig.overtake || false,
      overtakePath: window.ChatWidgetConfig.overtakePath || '/',
      initialButtons: window.ChatWidgetConfig.initialButtons || []
    } : defaultConfig;
    
    // Prevent multiple initializations
    if (window.IntendrChatWidgetInitialized) return;
    window.IntendrChatWidgetInitialized = true;
    
    // Initialize session ID early for analytics tracking
    let currentSessionId = '';
    
    // Analytics tracking function (declared early to avoid reference errors)
    async function trackAnalyticsEvent(eventType, additionalData = {}) {
      try {
        // Extract chatbot ID from webhook URL
        let chatbotId = '';
        try {
          const webhookUrl = config.webhook.url;
          const matches = webhookUrl.match(/\/webhook\/([^\/]+)/);
          if (matches && matches[1]) {
            chatbotId = matches[1].replace(/\/chat$/, '');
          }
        } catch (err) {
          console.error('Error extracting chatbot ID for analytics:', err);
          return;
        }

        if (!chatbotId) {
          console.warn('No chatbot ID found for analytics tracking');
          return;
        }

        // Prepare tracking data
        const trackingData = {
          chatbotId: chatbotId,
          sessionId: getAnalyticsSessionId(), // Use consistent analytics sessionId
          event: eventType,
          metadata: {
            chatSessionId: currentSessionId || null, // Individual chat conversation ID
            userAgent: navigator.userAgent,
            utmParams: window.initialUtmParameters || {},
            pageUrl: window.location.href,
            referrer: document.referrer || null,
            fingerprint: generateBrowserFingerprint(),
            language: navigator.language,
            screenResolution: screen.width + 'x' + screen.height,
            ip: userIP,
            timestamp: new Date().toISOString(),
            ...additionalData
          }
        };

        // Log the payload being sent for debugging
        console.log('📊 [Analytics] Sending payload:', JSON.stringify(trackingData, null, 2));
        console.log('📊 [Analytics] Event type:', eventType, '| Timestamp:', new Date().toLocaleTimeString());

        // Send to analytics API
        const response = await fetch('https://intendr.ai/api/analytics/track', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(trackingData)
        });

        if (response.ok) {
          console.log(`✅ [Analytics] ${eventType} tracked successfully - Status: ${response.status}`);
        } else {
          console.warn(`❌ [Analytics] Failed to track ${eventType} - Status: ${response.status}`);
          console.warn(`❌ [Analytics] Response:`, await response.text());
        }
      } catch (error) {
        console.warn('🚨 [Analytics] Tracking error:', error);
      }
    }

    // Generate browser fingerprint for deduplication
    function generateBrowserFingerprint() {
      try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Browser fingerprint', 2, 2);
        
        const fingerprint = [
          navigator.userAgent,
          navigator.language,
          screen.width + 'x' + screen.height,
          new Date().getTimezoneOffset(),
          canvas.toDataURL()
        ].join('|');
        
        // Simple hash function
        let hash = 0;
        for (let i = 0; i < fingerprint.length; i++) {
          const char = fingerprint.charCodeAt(i);
          hash = ((hash << 5) - hash) + char;
          hash = hash & hash;
        }
        
        return 'fp_' + Math.abs(hash).toString(36);
      } catch (error) {
        return 'fp_' + Math.random().toString(36).substring(2, 15);
      }
    }

    // Tracking pixel is now loaded immediately at script start (see above)
    
    // Track visitor directly since tracking pixel has endpoint bug
    const visitorTrackingKey = 'intendr_visitor_tracked_session';
    const sessionKey = window.sessionStorage.getItem(visitorTrackingKey);
    if (!sessionKey) {
      console.log('🎯 [Analytics] New visitor detected - tracking page load event directly');
      trackAnalyticsEvent('visitor');
      window.sessionStorage.setItem(visitorTrackingKey, 'true');
    } else {
      console.log('🔄 [Analytics] Returning visitor - skipping duplicate tracking');
    }
    console.log('🎯 [Analytics] Visitor tracking handled directly by chat widget (tracking pixel has endpoint bug)');
    
    // Track page visibility changes (after initial visitor tracking)
    document.addEventListener('visibilitychange', function() {
      if (!document.hidden) {
        console.log('👁️ [Analytics] Page visibility changed - user returned to tab');
        // User came back to page - track page view
        trackAnalyticsEvent('page_view');
      }
    });
    
    // Flag to track if user has manually closed the chat in this session
    let userManuallyClosedChat = false;
    
    // Function to check if chat was manually closed
    function checkIfChatWasManuallyClosed() {
      try {
        const chatState = sessionStorage.get(INTENDR_STORAGE_KEYS.chatState);
        if (chatState) {
          const state = JSON.parse(chatState);
          return state.manuallyClosed || false;
        }
      } catch (error) {
        console.error('Error reading chat state:', error);
      }
      return false;
    }

    // Function to save chat state
    function saveChatState(manuallyClosed) {
      try {
        const state = {
          manuallyClosed: manuallyClosed,
          timestamp: new Date().getTime()
        };
        sessionStorage.set(INTENDR_STORAGE_KEYS.chatState, JSON.stringify(state));
      } catch (error) {
        console.error('Error saving chat state:', error);
      }
    }
    
    // Function to show initial buttons
    function showInitialButtons() {
      // Simple check: if no initial buttons configured, return
      if (!config.initialButtons || config.initialButtons.length === 0) return;
      
      const buttonsContainer = chatContainer.querySelector('.initial-buttons-container');
      if (!buttonsContainer) return;
      
      // Don't interfere with action buttons - if container has action-buttons class, leave it alone
      if (buttonsContainer.classList.contains('action-buttons')) {
        return;
      }
      
      // Check if there are any user messages in the chat
      const messagesContainer = chatContainer.querySelector('.chat-messages');
      const userMessages = messagesContainer ? messagesContainer.querySelectorAll('.chat-message.user') : [];
      
      if (userMessages.length > 0) {
        // User has sent messages, hide buttons (only if not action buttons)
        buttonsContainer.style.display = 'none';
        return;
      }
      
      // No user messages, show the buttons
      buttonsContainer.innerHTML = '';
      
              config.initialButtons.forEach(buttonConfig => {
          const button = document.createElement('button');
          button.className = 'initial-button';
          button.textContent = buttonConfig.text;
          button.onclick = function() {
            // Send the predefined message (sendMessage handles both UI and backend)
            sendMessage(buttonConfig.message);
            // After sending, check buttons again (will hide them since user message now exists)
            setTimeout(showInitialButtons, 100);
          };
          buttonsContainer.appendChild(button);
        });
      
      buttonsContainer.style.display = 'grid';
    }
    
    // Function to hide initial buttons
    function hideInitialButtons() {
      const buttonsContainer = chatContainer.querySelector('.initial-buttons-container');
      if (buttonsContainer) {
        buttonsContainer.style.display = 'none';
      }
    }
    
    // Function to parse action tags from bot messages and generate action buttons
    function parseAndShowActionButtons(message) {
      console.log('[DEBUG] parseAndShowActionButtons called with message:', message);
      
      const buttonsContainer = chatContainer.querySelector('.initial-buttons-container');
      console.log('[DEBUG] buttonsContainer found:', !!buttonsContainer);
      if (!buttonsContainer) return message;
      
      // Clear any existing action buttons
      clearActionButtons();
      
      const actionButtons = [];
      let processedMessage = message;
      
      // Parse [phone] tags with optional btntext attribute
      const phoneRegex = /\[phone(?:\s+btntext="([^"]*)")?\](.*?)\[\/phone\]/g;
      let phoneMatch;
      while ((phoneMatch = phoneRegex.exec(message)) !== null) {
        const buttonText = phoneMatch[1] || 'Call Now';
        const phoneNumber = phoneMatch[2];
        const cleanPhone = phoneNumber.replace(/[^\d+]/g, '');
        
        // Remove the tag from the message
        processedMessage = processedMessage.replace(phoneMatch[0], '');
        
        // Add action button
        actionButtons.push({
          text: buttonText,
          action: () => window.open(`tel:${cleanPhone}`, '_self')
        });
      }
      
      // Parse [url] tags with optional btntext attribute
      const urlRegex = /\[url(?:\s+btntext="([^"]*)")?\](.*?)\[\/url\]/g;
      let urlMatch;
      while ((urlMatch = urlRegex.exec(message)) !== null) {
        const buttonText = urlMatch[1] || 'Visit Page';
        const url = urlMatch[2];
        
        // Remove the tag from the message
        processedMessage = processedMessage.replace(urlMatch[0], '');
        
        // Add action button
        actionButtons.push({
          text: buttonText,
          action: () => window.open(url, '_blank')
        });
      }
      
      // Parse [button] tags
      const buttonRegex = /\[button message="(.*?)"\](.*?)\[\/button\]/g;
      let buttonMatch;
      while ((buttonMatch = buttonRegex.exec(message)) !== null) {
        const buttonMessage = buttonMatch[1];
        const buttonText = buttonMatch[2];
        
        // Remove the tag from the message
        processedMessage = processedMessage.replace(buttonMatch[0], '');
        
        // Add action button
        actionButtons.push({
          text: buttonText,
          action: () => sendMessage(buttonMessage)
        });
      }

      // If no explicit action buttons were found, look for phone numbers in the message
      if (actionButtons.length === 0) {
        // Phone number regex that matches various formats
        const phoneNumberRegex = /(?:^|\s)(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})(?:\s|$)/g;
        let phoneNumberMatch;
        
        while ((phoneNumberMatch = phoneNumberRegex.exec(message)) !== null) {
          const fullMatch = phoneNumberMatch[0].trim();
          const cleanPhone = fullMatch.replace(/[^\d+]/g, '');
          
          // Create a button text that includes the location if mentioned
          let buttonText = 'Call Now';
          const locationMatch = message.match(/Aegis Living\s+([^,.]+)/i);
          if (locationMatch) {
            buttonText = `Call ${locationMatch[1]}`;
          }
          
          // Add action button
          actionButtons.push({
            text: buttonText,
            action: () => window.open(`tel:${cleanPhone}`, '_self')
          });
        }
      }
      
      // Show action buttons if any were found
      console.log('[DEBUG] actionButtons found:', actionButtons.length, actionButtons);
      if (actionButtons.length > 0) {
        console.log('[DEBUG] Calling showActionButtons');
        showActionButtons(actionButtons);
      } else {
        console.log('[DEBUG] No action buttons to show');
      }
      
      console.log('[DEBUG] Returning processed message:', processedMessage.trim());
      return processedMessage.trim();
    }
    
    // Function to show action buttons
    function showActionButtons(actionButtons) {
      console.log('[DEBUG] showActionButtons called with:', actionButtons);
      
      const buttonsContainer = chatContainer.querySelector('.initial-buttons-container');
      console.log('[DEBUG] showActionButtons - buttonsContainer found:', !!buttonsContainer);
      if (!buttonsContainer) return;
      
      // Clear container and add action buttons
      buttonsContainer.innerHTML = '';
      buttonsContainer.className = 'initial-buttons-container action-buttons';
      console.log('[DEBUG] Container cleared and class set');
      
      actionButtons.forEach((buttonConfig, index) => {
        console.log('[DEBUG] Creating button', index, ':', buttonConfig.text);
        const button = document.createElement('button');
        button.className = 'initial-button action-button';
        button.textContent = buttonConfig.text;
        button.onclick = function() {
          buttonConfig.action();
          // Clear action buttons after use
          clearActionButtons();
        };
        buttonsContainer.appendChild(button);
        console.log('[DEBUG] Button', index, 'appended. Button element:', button);
      });
      
      // Adjust grid layout based on number of buttons
      if (actionButtons.length === 1) {
        buttonsContainer.style.gridTemplateColumns = '1fr';
      } else if (actionButtons.length === 2) {
        buttonsContainer.style.gridTemplateColumns = '1fr 1fr';
      } else {
        buttonsContainer.style.gridTemplateColumns = '1fr 1fr';
      }
      
      buttonsContainer.style.display = 'grid';
      console.log('[DEBUG] Action buttons displayed, container style set to grid');
      console.log('[DEBUG] Final container state:', buttonsContainer);
      console.log('[DEBUG] Container children count:', buttonsContainer.children.length);
      console.log('[DEBUG] Container computed style display:', window.getComputedStyle(buttonsContainer).display);
      console.log('[DEBUG] Container computed style visibility:', window.getComputedStyle(buttonsContainer).visibility);
    }
    
    // Function to clear action buttons
    function clearActionButtons() {
      const buttonsContainer = chatContainer.querySelector('.initial-buttons-container');
      if (buttonsContainer) {
        buttonsContainer.classList.remove('action-buttons');
        buttonsContainer.style.display = 'none';
        buttonsContainer.innerHTML = '';
        
        // After clearing action buttons, check if we should show initial buttons
        setTimeout(showInitialButtons, 50);
      }
    }
    


    // Function to open chat
    function openChat() {
      if (!chatContainer.classList.contains('open')) {
        hidePromptBubble();
        promptBubbleShown = true;
        
        chatContainer.classList.add('open');
        toggleButton.classList.add('hidden');
        
        // Handle mobile
        if (window.innerWidth <= 600) {
          document.body.style.overflow = 'hidden';
        }
        
        // Clear any existing messages first
        messagesContainer.innerHTML = '';
        
        // Try to load existing session
        const sessionRestored = loadSession();
        
        if (!sessionRestored) {
          // Create new session
          inactivityMessageSent = false;
          currentSessionId = generateSessionId();
          // Show initial messages immediately
          sendInitialMessages();
          // Page context webhook disabled - generatePageSummary() removed
        }
        
        // Always check and show/hide initial buttons based on current messages
        showInitialButtons();
        
        // Save session after changes
        saveSession();
        
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        startInactivityTimer();
        clearTimeout(promptBubbleTimer);
      }
    }
    
    // UTM tracking function
    function extractUtmParameters(url) {
      const utmParams = {};
      try {
        const urlObj = new URL(url);
        const searchParams = new URLSearchParams(urlObj.search);
        
        // Standard UTM parameters
        const utmKeys = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'];
        utmKeys.forEach(function(key) {
          if (searchParams.has(key)) {
            utmParams[key] = searchParams.get(key);
          }
        });
        
        // Also check for any other custom utm parameters
        for (const [key, value] of searchParams.entries()) {
          if (key.startsWith('utm_') && !utmKeys.includes(key)) {
            utmParams[key] = value;
          }
        }
      } catch (error) {
        console.error('Error extracting UTM parameters:', error);
      }
      return utmParams;
    }
    
    // Store UTM parameters globally when first loaded
    window.initialUtmParameters = extractUtmParameters(window.location.href);
    console.log('Initial UTM Parameters:', window.initialUtmParameters);
    
    // Generate UUID
    function generateUUID() {
      if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
      } else {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0;
          const v = c === 'x' ? r : (r & 0x3 | 0x8);
          return v.toString(16);
        });
      }
    }

    // Get analytics sessionId for visitor/chat correlation (reuses existing)
    function getAnalyticsSessionId() {
      const trackingSessionKey = 'intendr_session_id';
      try {
        const existingTrackingSession = sessionStorage.getItem(trackingSessionKey);
        if (existingTrackingSession) {
          return existingTrackingSession;
        }
      } catch (error) {
        console.warn('Error reading tracking session from sessionStorage:', error);
      }
      
      // Generate new UUID for analytics
      const newAnalyticsSessionId = generateUUID();
      try {
        sessionStorage.setItem(trackingSessionKey, newAnalyticsSessionId);
      } catch (error) {
        console.warn('Error storing tracking session in sessionStorage:', error);
      }
      
      return newAnalyticsSessionId;
    }

    // Generate new chat session ID (always creates new for each conversation)
    function generateSessionId() {
      const newChatSessionId = generateUUID();
      console.log('🆕 Generated new chat sessionId:', newChatSessionId);
      return newChatSessionId;
    }



    // Enhanced lead conversion tracking
    function trackLeadConversion(leadData) {
      trackAnalyticsEvent('lead_conversion', {
        leadId: leadData.id || null,
        leadEmail: leadData.email || null,
        leadPhone: leadData.phone || null,
        conversionSource: 'chat_widget'
      });
    }

    // Make trackLeadConversion available globally for external use
    window.IntendrTrackLeadConversion = trackLeadConversion;
    
    // Format message with links and markdown
    function formatMessage(text) {
      if (!text) return '';
      
      // Check if the message contains HTML elements, and if so, don't process URLs
      const containsHtml = /<[a-z][\s\S]*>/i.test(text);
      
      // Convert markdown-style links [text](url) to HTML links
      text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
      
      // Handle raw URLs ONLY if the message doesn't contain HTML
      if (!containsHtml) {
        text = text.replace(/(https?:\/\/[^\s<]+)(?![^<]*>)/g, '<a href="$1" target="_blank">Visit Website</a>');
      }
      
      // Bold text between ** **
      text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
      
      // Italic text between * *
      text = text.replace(/\*([^*]+)\*/g, '<em>$1</em>');
      
      // Convert newlines to <br>
      text = text.replace(/\n/g, '<br>');
      
      return text;
    }
    
    // Function to append UTM parameters to URL
    function appendUtmToUrl(url) {
      try {
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        
        // Add the required UTM parameters
        params.set('utm_source', 'Intendr');
        params.set('utm_medium', 'chat');
        params.set('utm_campaign', INTENDR_SETTINGS.utmCampaign);
        
        // Rebuild the URL with the new parameters
        urlObj.search = params.toString();
        return urlObj.toString();
      } catch (error) {
        console.error('Error appending UTM parameters to URL:', error);
        // If URL parsing fails, return original URL
        return url;
      }
    }
    
    // Create thinking animation
    function showThinkingAnimation() {
      const thinkingDiv = document.createElement('div');
      thinkingDiv.className = 'thinking';
      thinkingDiv.innerHTML = `
          <span>${INTENDR_BRANDING.typingText}</span>
        <div class="dots">
        <div class="dot"></div>
        <div class="dot"></div>
        <div class="dot"></div>
        </div>
      `;
      thinkingDiv.id = 'thinking-animation';
      messagesContainer.appendChild(thinkingDiv);
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
      return thinkingDiv;
    }
    
    // Remove thinking animation
    function removeThinkingAnimation() {
      const thinkingElement = document.getElementById('thinking-animation');
      if (thinkingElement) {
        thinkingElement.remove();
      }
    }
    
    // Session persistence
    let sessionStorage = {
      get: function(key) {
        if (!isLocalStorageAvailable()) return null;
        try {
          return localStorage.getItem(key);
        } catch (e) {
          console.warn('Error reading from localStorage:', e);
          return null;
        }
      },
      set: function(key, value) {
        if (!isLocalStorageAvailable()) return;
        try {
          localStorage.setItem(key, value);
        } catch (e) {
          console.warn('Error writing to localStorage:', e);
        }
      },
      remove: function(key) {
        if (!isLocalStorageAvailable()) return;
        try {
          localStorage.removeItem(key);
        } catch (e) {
          console.warn('Error removing from localStorage:', e);
        }
      }
    };

    function saveSession() {
      if (currentSessionId) {
        try {
          const sessionData = {
            sessionId: currentSessionId,
            messages: Array.from(messagesContainer.children)
              .filter(function(el) { return el.classList.contains('chat-message'); })
              .map(function(msgEl) {
                return {
                  type: msgEl.classList.contains('user') ? 'user' : 'bot',
                  content: msgEl.classList.contains('user') ? msgEl.textContent : msgEl.innerHTML
                };
              }),
            inactivityMessageSent: inactivityMessageSent,
            promptBubbleShown: promptBubbleShown,
            timestamp: new Date().getTime(),
            utmParameters: window.initialUtmParameters || {}
          };
          
          sessionStorage.set(INTENDR_STORAGE_KEYS.chatSession, JSON.stringify(sessionData));
        } catch (error) {
          console.error('Error saving chat session:', error);
        }
      }
    }

    function loadSession() {
      try {
        const savedSession = sessionStorage.get(INTENDR_STORAGE_KEYS.chatSession);
        if (savedSession) {
          const sessionData = JSON.parse(savedSession);
          
          // Check if session is still valid (less than 24 hours old)
          const now = new Date().getTime();
          const sessionAge = now - sessionData.timestamp;
          
          if (sessionAge < INTENDR_SETTINGS.sessionValidity) {
            // Clear the messages container completely before restoring
            messagesContainer.innerHTML = '';
            
            // Restore session ID
            currentSessionId = sessionData.sessionId;
            
            // Restore inactivity message status
            if (sessionData.inactivityMessageSent) {
              inactivityMessageSent = true;
            }
            
            // Restore prompt bubble state
            if (sessionData.promptBubbleShown) {
              promptBubbleShown = true;
            }
            
            // Restore UTM parameters if they exist in the session
            if (sessionData.utmParameters) {
              window.initialUtmParameters = sessionData.utmParameters;
            }
            
            // Restore messages
            if (sessionData.messages && sessionData.messages.length > 0) {
              sessionData.messages.forEach(function(msg) {
                const messageDiv = document.createElement('div');
                messageDiv.className = 'chat-message ' + msg.type;
                if (msg.type === 'user') {
                  messageDiv.textContent = msg.content;
                } else {
                  messageDiv.innerHTML = msg.content;
                }
                messagesContainer.appendChild(messageDiv);
              });
              
              // After restoring messages, check buttons
              setTimeout(showInitialButtons, 100);
            }
            
            return true;
          }
          // Session too old, clear it
          sessionStorage.remove(INTENDR_STORAGE_KEYS.chatSession);
        }
      } catch (error) {
        console.error('Error loading saved chat session:', error);
        sessionStorage.remove(INTENDR_STORAGE_KEYS.chatSession);
      }
      return false;
    }
    
    // Inactivity detection for chat window
    let inactivityTimer;
    let inactivityMessageSent = false;
    
    function startInactivityTimer() {
      clearTimeout(inactivityTimer);
    }
    
    function resetInactivityTimer() {
      if (chatContainer.classList.contains('open')) {
        clearTimeout(inactivityTimer);
          startInactivityTimer();
      }
    }
    
    function resetInactivityState() {
      clearTimeout(inactivityTimer);
      startInactivityTimer();
    }
    
    // Prompt bubble functionality
    let promptBubbleTimer;
    let promptBubbleShown = false;
    
    function startPromptBubbleTimer() {
      // Only start timer if prompt hasn't been shown yet
      if (!promptBubbleShown) {
        promptBubbleTimer = setTimeout(function() {
          showPromptBubble();
        }, INTENDR_SETTINGS.promptBubbleTimeout);
      }
    }
    
    function showPromptBubble() {
      // Only show if chat isn't open and prompt hasn't been shown
      if (!chatContainer.classList.contains('open') && !promptBubbleShown) {
        const promptBubble = document.createElement('div');
        promptBubble.className = 'prompt-bubble';
        promptBubble.textContent = 'Have a question?';
        promptBubble.id = 'prompt-bubble';
        
        // Add click handler to open chat
        promptBubble.addEventListener('click', function() {
          // Hide prompt bubble
          hidePromptBubble();
          
          // Open chat
          toggleButton.click();
        });
        
        widgetContainer.appendChild(promptBubble);
        promptBubbleShown = true;
        
        // Save session state
        saveSession();
      }
    }
    
    function hidePromptBubble() {
      const promptBubble = document.getElementById('prompt-bubble');
      if (promptBubble) {
        promptBubble.remove();
      }
    }
    
    // Styles
    const styles = `
      :root {
        --chat--color-primary: ${config.style.primaryColor};
        --chat--color-secondary: ${config.style.secondaryColor};
      }
      div#notificationDisplay {
        display: none !important;
      }
      iframe#c1-leads-assistant {
        display: none !important;
      }
      .intendr-chat-widget {
        font-family: 'Geist Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      .intendr-chat-widget .chat-container {
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 2147483647;
        width: 380px;
        height: 600px;
        background: #ffffff;
        border-radius: 12px !important;
        box-shadow: 0 8px 32px rgba(133, 79, 255, 0.15);
        border: 1px solid rgba(133, 79, 255, 0.2);
        overflow: hidden;
        opacity: 0;
        transform-origin: bottom right;
        transform: scale(0);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        pointer-events: none;
        display: flex;
        flex-direction: column;
        visibility: hidden;
      }
      @media screen and (max-width: 600px) {
        .intendr-chat-widget .chat-container {
          width: 100%;
          height: 100%;
          bottom: 0;
          right: 0;
          border-radius: 0;
          box-shadow: none;
        }
        .intendr-chat-widget .chat-container.position-left {
          left: 0;
        }
      }
      .intendr-chat-widget .chat-container.position-left {
        right: auto;
        left: 20px;
        transform-origin: bottom left;
      }
      .intendr-chat-widget .chat-container.open {
        opacity: 1;
        transform: scale(1);
        pointer-events: all;
        visibility: visible;
      }
      .intendr-chat-widget .brand-header {
        padding: 16px;
        display: flex;
        align-items: center;
        gap: 12px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        position: relative;
        background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
      }
      .intendr-chat-widget .close-button {
        position: absolute;
        right: 16px;
        top: 50%;
        transform: translateY(-50%);
        background: none;
        border: none;
        cursor: pointer;
        font-size: 20px;
        opacity: 0.8;
        color: #ffffff;
      }
      .intendr-chat-widget .brand-header img {
        width: 32px;
        height: 32px;
        filter: brightness(0) invert(1);
      }
      .intendr-chat-widget .brand-header span {
        font-size: 18px;
        font-weight: 500;
        color: #ffffff;
      }
      .intendr-chat-widget .chat-interface {
        display: flex;
        flex-direction: column;
        height: 100%;
      }
      .intendr-chat-widget .chat-messages {
        flex: 1;
        overflow-y: auto;
        padding: 20px;
        display: flex;
        flex-direction: column;
      }
      .intendr-chat-widget .chat-message {
        padding: 12px 16px;
        margin: 8px 0;
        border-radius: 12px;
        max-width: 80%;
        word-wrap: break-word;
        font-size: 14px;
        line-height: 1.5;
      }
      .intendr-chat-widget .chat-message.user {
        background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
        color: #fff;
        align-self: flex-end;
        box-shadow: 0 4px 12px rgba(133, 79, 255, 0.2);
        border-radius: 12px;
        padding: 12px 16px;
        margin: 8px 0;
        max-width: 80%;
        word-wrap: break-word;
        font-size: 14px;
        line-height: 1.5;
      }
      .intendr-chat-widget .chat-message.bot {
        background: #ffffff;
        border: 1px solid rgba(133, 79, 255, 0.2);
        color: #333;
        align-self: flex-start;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
      }
      .intendr-chat-widget .chat-message.bot a {
        color: var(--chat--color-primary);
        text-decoration: none;
        font-weight: 500;
      }
      .intendr-chat-widget .chat-message.bot a:hover {
        text-decoration: underline;
      }
      .intendr-chat-widget .chat-message.bot a:hover {
        text-decoration: underline;
      }
      .intendr-chat-widget .chat-input {
        padding: 16px;
        border-top: 1px solid rgba(133, 79, 255, 0.1);
        display: flex;
        gap: 8px;
      }
      .intendr-chat-widget .chat-input textarea {
        flex: 1 !important;
        padding: 12px !important;
        border: 1px solid rgba(133, 79, 255, 0.2) !important;
        border-radius: 8px !important;
        resize: none !important;
        font-family: inherit !important;
        font-size: 14px !important;
        height: auto !important;
        min-height: 40px !important;
        max-height: 120px !important;
        width: auto !important;
        box-sizing: border-box !important;
      }
      .intendr-chat-widget .chat-input button {
        background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
        color: #fff;
        border: none;
        border-radius: 8px;
        padding: 0 18px;
        cursor: pointer;
        font-weight: 500;
        font-size: 16px;
        height: 40px;
        min-width: 40px;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .intendr-chat-widget .chat-input button svg {
        fill: #fff;
        stroke: #fff;
      }
    .intendr-chat-widget .chat-toggle {
      position: fixed;
      bottom: 60px;
      right: 20px;
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
      color: white;
      border: none;
      cursor: pointer;
      box-shadow: 0 4px 12px var(--chat--color-primary);
      z-index: 2147483647;
      border-radius: 30px !important;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      opacity: 1;
      transform: scale(1);
    }
    .intendr-chat-widget .phone-toggle {
      bottom: 60px !important;
    }
    
    .intendr-chat-widget .chat-toggle.hidden {
      opacity: 0;
      transform: scale(0.8);
      pointer-events: none;
    }
    
    .intendr-chat-widget .chat-toggle-content {
      display: flex;
      align-items: center;
      gap: 12px;
      position: relative;
    }
    
    .intendr-chat-widget .chat-toggle svg {
      width: 24px;
      height: 24px;
      fill: currentColor;
      color: white;
    }
    
    .intendr-chat-widget .chat-toggle-text {
      font-size: 16px;
      font-weight: 500;
      white-space: nowrap;
      line-height: 24px;
    }
    
    .intendr-chat-widget .online-indicator {
      position: absolute;
      top: -20px;
      right: -4px;
      width: 12px;
      height: 12px;
      background-color: #22c55e;
      border-radius: 50%;
      border: 2px solid white;
      animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
      0% {
        box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4);
      }
      70% {
        box-shadow: 0 0 0 10px rgba(34, 197, 94, 0);
      }
      100% {
        box-shadow: 0 0 0 0 rgba(34, 197, 94, 0);
      }
    }
    
    /* Update mobile styles for online indicator */
    @media screen and (max-width: 600px) {
      .intendr-chat-widget .chat-toggle {
        width: 60px;
        height: 60px;
        padding: 0;
        justify-content: center;
      }
    
      .intendr-chat-widget .chat-toggle-text {
        display: none;
      }
      
      .intendr-chat-widget .online-indicator {
        top: -20px;
        right: -4px;
      }
    }
    
        .intendr-chat-widget .chat-toggle.position-left {
          right: auto;
          left: 20px;
        }
        .intendr-chat-widget .chat-toggle svg {
          width: 24px;
          height: 24px;
          fill: currentColor;
        }
        .intendr-chat-widget .thinking {
          display: flex;
          align-items: center;
          padding: 12px 16px;
          margin: 8px 0;
          border-radius: 12px;
          max-width: 80%;
          align-self: flex-start;
          background: #fff;
          border: 1px solid rgba(133, 79, 255, 0.2);
          gap: 8px;
        }
        .intendr-chat-widget .thinking span {
          color: #666;
          font-size: 14px;
        }
        .intendr-chat-widget .dots {
          display: flex;
          gap: 2px;
        }
        .intendr-chat-widget .dot {
          height: 8px;
          width: 8px;
          background-color: var(--chat--color-primary);
          border-radius: 50%;
          display: inline-block;
          opacity: 0.4;
          animation: dot-typing 1.4s infinite ease-in-out;
        }
        .intendr-chat-widget .dot:nth-child(1) { animation-delay: 0s; }
        .intendr-chat-widget .dot:nth-child(2) { animation-delay: 0.2s; }
        .intendr-chat-widget .dot:nth-child(3) { animation-delay: 0.4s; }
        /* Prompt bubble styles */
        .intendr-chat-widget .prompt-bubble {
          position: absolute;
          bottom: 90px;
          right: 10px;
          background: white;
          color: var(--chat--color-primary);
          padding: 8px 14px;
          border-radius: 18px;
          font-size: 14px;
          font-weight: 500;
          box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
          cursor: pointer;
          z-index: 2147483646;
          border: 1px solid rgba(133, 79, 255, 0.2);
          animation: bounce-in 0.5s;
        }
        /* Position the prompt bubble on the left if chat is on the left */
        .intendr-chat-widget .chat-toggle.position-left + .prompt-bubble {
          right: auto;
          left: 10px;
        }
        @keyframes bounce-in {
          0% { transform: scale(0.5); opacity: 0; }
          50% { transform: scale(1.05); opacity: 0.9; }
          100% { transform: scale(1); opacity: 1; }
        }
        @keyframes dot-typing {
          0%, 60%, 100% { opacity: 0.4; transform: scale(1); }
          30% { opacity: 1; transform: scale(1.2); }
        }
        /* Initial buttons styles */
        .intendr-chat-widget .initial-buttons-container {
          padding: 10px 10px 0px 10px;
          border-top: 1px solid rgba(133, 79, 255, 0.1);
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 8px;
        }
        .intendr-chat-widget .initial-button {
          background: white;
          border: 1px solid rgba(133, 79, 255, 0.2);
          border-radius: 8px;
          padding: 12px 8px;
          cursor: pointer;
          transition: all 0.2s ease;
          text-align: center;
          font-size: 13px;
          font-weight: 500;
          color: var(--chat--color-primary);
        }
        .intendr-chat-widget .initial-button:hover {
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
          color: white;
          border-color: transparent;
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(133, 79, 255, 0.3);
        }
        /* Action buttons (from bot messages) */
        .intendr-chat-widget .action-buttons {
          border-top: 2px solid rgba(133, 79, 255, 0.3);
          background: rgba(133, 79, 255, 0.02);
          padding: 10px;
          display: grid;
          gap: 8px;
        }
        .intendr-chat-widget .action-button {
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
          color: white;
          border: none;
          font-weight: 600;
          padding: 12px 16px;
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s ease;
          text-align: center;
          font-size: 14px;
          line-height: 1.4;
          width: 100%;
          box-sizing: border-box;
        }
        .intendr-chat-widget .action-button:hover {
          background: linear-gradient(135deg, #5a67d8 0%, #6b5b95 100%);
          transform: translateY(-2px);
          box-shadow: 0 6px 16px rgba(133, 79, 255, 0.4);
        }

        @media screen and (max-width: 600px) {
          .intendr-chat-widget .action-buttons {
            padding: 8px;
            gap: 6px;
          }
          .intendr-chat-widget .action-button {
            padding: 10px 12px;
            font-size: 13px;
            border-radius: 6px;
          }
        }

        /* Defensive styles for widget overlays only */
        .intendr-widget-overlay {
          position: fixed !important;
          z-index: 2147483648 !important;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
          box-sizing: border-box !important;
          /* Reset common problematic properties */
          margin: 0 !important;
          transform: none !important;
          animation: none !important;
          transition: none !important;
        }

        .intendr-widget-overlay * {
          box-sizing: border-box !important;
          font-family: inherit !important;
        }

        .intendr-widget-overlay input {
          appearance: none !important;
          -webkit-appearance: none !important;
          -moz-appearance: none !important;
        }

        .intendr-widget-overlay button {
          cursor: pointer !important;
          user-select: none !important;
          -webkit-user-select: none !important;
          -moz-user-select: none !important;
        }

        /* Defensive styles for chat input textarea only */
        .intendr-chat-widget .chat-input textarea {
          width: 100% !important;
          min-height: 40px !important;
          max-height: 120px !important;
          height: 40px !important;
          padding: 12px 50px 12px 16px !important;
          margin: 0 !important;
          border: 1px solid #e0e0e0 !important;
          border-radius: 6px !important;
          font-size: 14px !important;
          line-height: 1.2 !important;
          background: white !important;
          color: #333 !important;
          resize: none !important;
          outline: none !important;
          box-sizing: border-box !important;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
          display: block !important;
          position: relative !important;
          overflow: hidden !important;
          overflow-y: auto !important;
          word-wrap: break-word !important;
          white-space: nowrap !important;
          vertical-align: top !important;
          text-align: left !important;
          letter-spacing: normal !important;
          word-spacing: normal !important;
          text-indent: 0 !important;
          text-transform: none !important;
          text-decoration: none !important;
        }

        .intendr-chat-widget .chat-input textarea:focus {
          border-color: var(--chat--color-primary) !important;
          box-shadow: 0 0 0 2px rgba(133, 79, 255, 0.2) !important;
        }

        /* Defensive styles for thinking/typing indicator */
        .intendr-chat-widget .thinking {
          background: white !important;
          border: 1px solid #e0e0e0 !important;
          border-radius: 15px !important;
          padding: 8px 12px !important;
          margin: 8px 0 !important;
          display: inline-block !important;
          width: auto !important;
          max-width: none !important;
          float: left !important;
          clear: both !important;
          box-sizing: border-box !important;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
          font-size: 14px !important;
          line-height: 1.4 !important;
          color: #666 !important;
          text-align: left !important;
          letter-spacing: normal !important;
          word-spacing: normal !important;
          text-indent: 0 !important;
          text-transform: none !important;
          text-decoration: none !important;
        }

        .intendr-chat-widget .thinking span {
          margin: 0 !important;
          padding: 0 !important;
          font-family: inherit !important;
          font-size: inherit !important;
          line-height: inherit !important;
          color: inherit !important;
        }

        /* Defensive styles for action buttons */
        .intendr-chat-widget .initial-button,
        .intendr-chat-widget .action-button {
          padding: 12px 20px !important;
          border: none !important;
          border-radius: 8px !important;
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%) !important;
          color: white !important;
          font-weight: 600 !important;
          font-size: 14px !important;
          line-height: 1.2 !important;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
          cursor: pointer !important;
          transition: all 0.2s ease !important;
          box-shadow: 0 2px 8px rgba(133, 79, 255, 0.3) !important;
          display: inline-block !important;
          text-align: center !important;
          text-decoration: none !important;
          box-sizing: border-box !important;
          min-height: auto !important;
          height: auto !important;
          max-height: none !important;
          vertical-align: top !important;
          letter-spacing: normal !important;
          word-spacing: normal !important;
          text-indent: 0 !important;
          text-transform: none !important;
          outline: none !important;
          user-select: none !important;
          -webkit-user-select: none !important;
          -moz-user-select: none !important;
        }

        .intendr-chat-widget .initial-button:hover,
        .intendr-chat-widget .action-button:hover {
          background: linear-gradient(135deg, var(--chat--color-secondary) 0%, var(--chat--color-primary) 100%) !important;
          transform: translateY(-2px) !important;
          box-shadow: 0 6px 16px rgba(133, 79, 255, 0.4) !important;
        }
      `;
      
      // Inject styles
      const styleSheet = document.createElement('style');
      styleSheet.textContent = styles;
      document.head.appendChild(styleSheet);
      
      // Create DOM elements
      const widgetContainer = document.createElement('div');
      widgetContainer.className = 'intendr-chat-widget';
      
      const chatContainer = document.createElement('div');
      chatContainer.className = `chat-container${config.style.position === 'left' ? ' position-left' : ''}`;
      
      const chatInterfaceHTML = `
        <div class="chat-interface">
          <div class="brand-header">
            <img src="${config.branding.logo}" alt="${config.branding.name}">
            <span>${config.branding.name}</span>
            <button class="close-button">×</button>
          </div>
          <div class="chat-messages"></div>
          <div class="initial-buttons-container" style="display: none;"></div>
          <div class="chat-input">
            <textarea placeholder="Type your message here..." rows="1"></textarea>
            <button type="submit">Send</button>
          </div>
        </div>
      `;
      
      chatContainer.innerHTML = chatInterfaceHTML;
      
      const toggleButton = document.createElement('button');
      toggleButton.className = `chat-toggle${config.style.position === 'left' ? ' position-left' : ''}`;
      toggleButton.innerHTML = `
        <div class="chat-toggle-content">
          <div class="online-indicator"></div>
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
            <path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z" fill="currentColor"/>
          </svg>
          <span class="chat-toggle-text">Chat with us!</span>
        </div>
      `;
      
      // Position the chat toggle button to the left of where phone button will be
      if (config.style.position !== 'left') {
        toggleButton.style.right = '85px';
      }
      
      widgetContainer.appendChild(chatContainer);
      widgetContainer.appendChild(toggleButton);
      
      // Create phone call button
      const phoneButton = document.createElement('button');
      phoneButton.className = `chat-toggle phone-toggle${config.style.position === 'left' ? ' position-left' : ''}`;
      phoneButton.innerHTML = `
        <div class="chat-toggle-content">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
          </svg>
        </div>
      `;
      
      // Style the phone button - keep at original position
      phoneButton.style.position = 'fixed';
      phoneButton.style.bottom = '20px';
      phoneButton.style.right = config.style.position === 'left' ? '20px' : '20px'; // Right side positioning
      phoneButton.style.width = '60px';
      phoneButton.style.height = '60px';
      phoneButton.style.borderRadius = '50%';
      phoneButton.style.display = 'flex';
      phoneButton.style.alignItems = 'center';
      phoneButton.style.justifyContent = 'center';
      phoneButton.style.background = 'linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%)';
      phoneButton.style.color = 'white';
      phoneButton.style.border = 'none';
      phoneButton.style.cursor = 'pointer';
      phoneButton.style.boxShadow = '0 4px 12px var(--chat--color-primary)';
      phoneButton.style.zIndex = '2147483646';
      phoneButton.style.padding = '0';
      
      // Remove the position adjustment of the chat toggle button
      // Let both buttons sit in their natural positions
      
      // Phone button click handler
      phoneButton.onclick = function(e) {
        e.stopPropagation();
        
        // Remove any existing tooltip
        const existingTooltip = document.getElementById('intendr-phone-tooltip');
        if (existingTooltip) {
          existingTooltip.remove();
          return;
        }
        
        // Create tooltip - use a more compact style matching the in-chat tooltip
        const tooltip = document.createElement('div');
        tooltip.id = 'intendr-phone-tooltip';
        tooltip.className = 'intendr-widget-overlay';
        
        // Apply defensive styles
        Object.assign(tooltip.style, {
          position: 'fixed',
          bottom: '130px',
          right: config.style.position === 'left' ? '20px' : '20px',
          background: 'white',
          boxShadow: '0 2px 12px rgba(0,0,0,0.15)',
          borderRadius: '8px',
          padding: '10px',
          zIndex: '2147483646',
          width: '200px',
          boxSizing: 'border-box',
          margin: '0',
          border: 'none',
          outline: 'none',
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
          fontSize: '14px',
          lineHeight: '1.4',
          color: '#333',
          textAlign: 'left'
        })
        
        // Add a CSS pointer to connect tooltip to phone button
        const pointerStyle = document.createElement('style');
        pointerStyle.textContent = `
          #intendr-phone-tooltip::after {
            content: '';
            position: absolute;
            bottom: -10px;
            right: 30px;
            margin-left: -10px;
            border-width: 10px 10px 0;
            border-style: solid;
            border-color: white transparent transparent transparent;
            filter: drop-shadow(0 2px 2px rgba(0,0,0,0.1));
          }
        `;
        document.head.appendChild(pointerStyle);
        
        tooltip.innerHTML = `
          <div style="font-size:1.1rem;font-weight:600;margin-bottom:8px;color:#333;">Prefer to talk on the phone?</div>
          <div style="font-size:0.9rem;color:#666;margin-bottom:12px;">I can ring you now at the number you enter below to make things easier!</div>
          <div id="intendr-phone-input-container" style="width:100% !important;box-sizing:border-box !important;margin:0 !important;padding:0 !important;">
            <input type="tel" id="intendr-direct-phone-input" placeholder="(123) 123-1234" style="width:100% !important;padding:10px !important;border-radius:4px !important;border:1px solid #ccc !important;margin:0 0 6px 0 !important;font-size:1rem !important;box-sizing:border-box !important;font-family:inherit !important;line-height:normal !important;background:white !important;color:#333 !important;outline:none !important;text-align:left !important;">
            <div id="intendr-direct-phone-validation" style="color:#c00 !important;margin:0 0 6px 0 !important;text-align:left !important;display:none !important;font-size:0.85rem !important;font-family:inherit !important;line-height:1.2 !important;padding:0 !important;"></div>
            <button id="intendr-direct-start-call" style="width:100% !important;padding:10px !important;border-radius:4px !important;background:linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%) !important;color:#fff !important;font-weight:500 !important;font-size:1rem !important;border:none !important;cursor:pointer !important;box-sizing:border-box !important;box-shadow:0 4px 12px rgba(133, 79, 255, 0.2) !important;font-family:inherit !important;line-height:normal !important;text-align:center !important;margin:0 !important;outline:none !important;">Start Call</button>
          </div>
          <div id="intendr-direct-call-error" style="color:#c00;margin-top:8px;text-align:center;display:none;"></div>
        `;
        
        // Add the tooltip to the body, not as a child of the button
        document.body.appendChild(tooltip);
        
        // Correctly position the tooltip after it's been created
        const phoneRect = phoneButton.getBoundingClientRect();
        const tooltipRect = tooltip.getBoundingClientRect();
        
        // Position tooltip to align the pointer with the center of the phone button
        // Add mobile-specific positioning
        if (window.innerWidth <= 600) {
          tooltip.style.width = '280px';
          tooltip.style.left = '20px';
          tooltip.style.right = 'auto';
          tooltip.style.transform = 'none';
          tooltip.style.bottom = '90px';
          tooltip.style.top = 'auto';
        } else {
          tooltip.style.right = `${window.innerWidth - phoneRect.right - (phoneRect.width / 2) + 30}px`;
        }
        
        // Close tooltip when clicking outside
        document.addEventListener('click', function closeDirectTooltip(e) {
          if (!tooltip.contains(e.target) && e.target !== phoneButton) {
            tooltip.remove();
            document.removeEventListener('click', closeDirectTooltip);
          }
        });
        
        // Add validation functions for direct phone input
        const directPhoneInput = document.getElementById('intendr-direct-phone-input');
        const directValidationDiv = document.getElementById('intendr-direct-phone-validation');
        
        function validateDirectPhoneNumber(phone) {
          const digits = phone.replace(/\D/g, '');
          if (digits.length === 10) {
            return { valid: true, formatted: `+1${digits}` };
          } else if (digits.length === 11 && digits.startsWith('1')) {
            return { valid: true, formatted: `+${digits}` };
          } else {
            return { 
              valid: false, 
              error: 'Please enter a valid US phone number (10 digits)' 
            };
          }
        }
        
        function showDirectValidationError(message) {
          directValidationDiv.textContent = message;
          directValidationDiv.style.display = 'block';
          directPhoneInput.style.borderColor = '#c00';
        }
        
        function clearDirectValidationError() {
          directValidationDiv.style.display = 'none';
          directPhoneInput.style.borderColor = '#ccc';
        }
        
        // Add real-time validation
        directPhoneInput.addEventListener('input', function() {
          const value = this.value.trim();
          if (value) {
            const validation = validateDirectPhoneNumber(value);
            if (validation.valid) {
              clearDirectValidationError();
            } else {
              showDirectValidationError(validation.error);
            }
          } else {
            clearDirectValidationError();
          }
        });
        
        // Handle the call button click
        document.getElementById('intendr-direct-start-call').onclick = async function() {
          const phone = directPhoneInput.value.trim();
          const errorDiv = document.getElementById('intendr-direct-call-error');
          
          // Clear previous errors
          errorDiv.style.display = 'none';
          clearDirectValidationError();
          
          if (!phone) {
            showDirectValidationError('Please enter your phone number.');
            return;
          }
          
          const validation = validateDirectPhoneNumber(phone);
          if (!validation.valid) {
            showDirectValidationError(validation.error);
            return;
          }
          
          try {
            // Disable input while processing
            directPhoneInput.disabled = true;
            document.getElementById('intendr-direct-start-call').disabled = true;
            document.getElementById('intendr-direct-start-call').textContent = 'Connecting...';
            
            // Use formatted phone number with +1
            await initiateVoiceCall('phone_raw', validation.formatted);
            
            // Show success message
            errorDiv.style.color = '#090';
            errorDiv.textContent = 'Call initiated! Please answer your phone.';
            errorDiv.style.display = 'block';
            
            // Remove tooltip after a delay
            setTimeout(() => {
              tooltip.remove();
            }, 3000);
            
          } catch (err) {
            errorDiv.textContent = err.message || "Couldn't connect your call. Please try again.";
            errorDiv.style.display = 'block';
            
            // Re-enable input
            directPhoneInput.disabled = false;
            document.getElementById('intendr-direct-start-call').disabled = false;
            document.getElementById('intendr-direct-start-call').textContent = 'Start Call';
          }
        };
      };
      
      widgetContainer.appendChild(phoneButton);
      document.body.appendChild(widgetContainer);
      
      // Get references to elements
      const chatInterface = chatContainer.querySelector('.chat-interface');
      const messagesContainer = chatContainer.querySelector('.chat-messages');
      const textarea = chatContainer.querySelector('textarea');
      const sendButton = chatContainer.querySelector('button[type="submit"]');
      const closeButton = chatContainer.querySelector('.close-button');
      
      // Add event listeners
      toggleButton.addEventListener('click', function() {
        if (!chatContainer.classList.contains('open')) {
          chatContainer.classList.add('open');
          toggleButton.classList.add('hidden');
          
          // Handle mobile
          if (window.innerWidth <= 600) {
            document.body.style.overflow = 'hidden';
          }
          
          // Clear any existing messages first
          messagesContainer.innerHTML = '';
          
          // Try to load existing session
          const sessionRestored = loadSession();
          
          if (!sessionRestored) {
            // Create new session
            inactivityMessageSent = false;
            currentSessionId = generateSessionId();
            
            // Page context webhook disabled - sending initial messages directly
            sendInitialMessages();
          }
          
          // Save session after changes
          saveSession();
          
          messagesContainer.scrollTop = messagesContainer.scrollHeight;
          startInactivityTimer();
          clearTimeout(promptBubbleTimer);
        }
      });

      closeButton.addEventListener('click', function() {
        // Track session end before closing
        const messagesContainer = document.querySelector('.chat-messages');
        const userMessages = messagesContainer ? messagesContainer.querySelectorAll('.chat-message.user') : [];
        const botMessages = messagesContainer ? messagesContainer.querySelectorAll('.chat-message.bot') : [];
        
        if (userMessages.length > 0) {
          trackAnalyticsEvent('session_end', {
            messageCount: userMessages.length + botMessages.length,
            userMessageCount: userMessages.length,
            botMessageCount: botMessages.length,
            sessionDuration: Date.now() - (new Date().getTime() || Date.now())
          });
        }

        if (overlayDiv) {
          hideOvertakeModal();
        } else {
          hideChat();
        }
        userManuallyClosedChat = true;
        saveChatState(true);
        if (window.innerWidth <= 600) document.body.style.overflow = '';
      });

      // Handle textarea input
      textarea.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';
      });

      // Enhanced handleMessageSend to support close commands
      function handleMessageSend() {
        // Find the current active textarea - try window reference first, 
        // then global textarea, then query for it directly
        const input = window.intendrTextarea || 
                     textarea || 
                     document.querySelector('.chat-input textarea');
                     
        if (!input) {
          console.error('[Intendr] No textarea found for message sending');
          return;
        }
        
        const message = input.value.trim();
        if (!message) return;
        
        // Check for close commands
        const closeCommands = ['close', 'close chat', 'exit', 'quit', 'dismiss'];
        if (closeCommands.includes(message.toLowerCase())) {
          if (overlayDiv) hideOvertakeModal();
          else hideChat();
          input.value = '';
          return;
        }
        
        // Clear any action buttons before sending new message
        clearActionButtons();
        
        sendMessage(message);
        input.value = '';
        input.style.height = 'auto';
        
        // After sending message, check buttons (will hide them since user message now exists)
        setTimeout(showInitialButtons, 100);
      }

      sendButton.addEventListener('click', handleMessageSend);
      textarea.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          handleMessageSend();
        }
      });

      // Handle window resize
      window.addEventListener('resize', function() {
        if (window.innerWidth <= 600) {
          if (chatContainer.classList.contains('open')) {
            document.body.style.overflow = 'hidden';
          }
        } else {
          document.body.style.overflow = '';
        }
      });
      
      // Store page summary globally
      let pageSummary = null;
      let summaryFetchTimeout = null;
      
      // Function to determine page type
      function determinePageType() {
        const path = window.location.pathname.toLowerCase();
        if (path.includes('/products/') || path.includes('/inventory/') || path.includes('/catalog/')) {
          return 'products';
        } else if (path.includes('/services/') || path.includes('/service/')) {
          return 'services';
        } else if (path.includes('/about')) {
          return 'about';
        } else if (path.includes('/contact')) {
          return 'contact';
        } else if (path.includes('/pricing') || path.includes('/plans')) {
          return 'pricing';
        } else if (path.includes('/support') || path.includes('/help')) {
          return 'support';
        } else if (path === '/' || path === '/index.html') {
          return 'home';
        }
        return 'other';
      }

      // Function to clean HTML content
      function cleanHtmlContent(element) {
        if (!element) return '';
        
        // Clone the entire document body to get all content
        const clone = document.body.cloneNode(true);
        
        // Remove all chat containers and their contents
        const chatContainers = clone.querySelectorAll('.chat-container');
        chatContainers.forEach(container => container.remove());
        
        // Remove all script, style, and other non-content elements
        const elementsToRemove = [
          'script', 'style', 'noscript', 'iframe', 'svg', 'img', 
          'button', 'input', 'select', 'textarea', 'form',
          'link', 'meta', 'head', 'style', 'script'
        ];
        
        elementsToRemove.forEach(selector => {
          const elements = clone.querySelectorAll(selector);
          elements.forEach(el => el.remove());
        });
        
        // Get all text content
        let text = clone.textContent || clone.innerText;
        
        // Clean up the text
        text = text
          .replace(/\s+/g, ' ')  // Replace multiple spaces with single space
          .replace(/\n+/g, ' ')  // Replace newlines with space
          .replace(/\t+/g, ' ')  // Replace tabs with space
          .replace(/\r+/g, ' ')  // Replace carriage returns with space
          .replace(/\s+/g, ' ')  // Clean up any remaining multiple spaces
          .trim();
        
        // Remove any remaining HTML tags
        text = text.replace(/<[^>]*>/g, '');
        
        // Remove any special characters that might be causing issues
        text = text.replace(/[\u200B-\u200D\uFEFF]/g, '');
        
        return text;
      }

      // Function to extract navigation links
      function collectNavigationLinks() {
        // Check if we already have stored links
        const storedLinks = localStorage.getItem(INTENDR_STORAGE_KEYS.navLinks)
        if (storedLinks) return JSON.parse(storedLinks)

        const links = new Set()
        
        // Function to process links from an element
        function processLinks(element) {
            if (!element) return
            const anchorElements = element.querySelectorAll('a[href]')
            anchorElements.forEach(anchor => {
                const href = anchor.getAttribute('href')
                const text = anchor.textContent.trim()
                if (href && !href.startsWith('#') && !href.startsWith('javascript:') && text) {
                    // Convert relative URLs to absolute
                    const absoluteUrl = new URL(href, window.location.origin).href
                    // Store as object with text and url
                    links.add(JSON.stringify({
                        text: text,
                        url: absoluteUrl
                    }))
                }
            })
        }

        // Try to find navigation elements
        const navElement = document.querySelector('nav')
        const headerElement = document.querySelector('header')
        
        // Process nav and header if they exist
        if (navElement) processLinks(navElement)
        if (headerElement) processLinks(headerElement)

        // If no links found in nav/header, look for elements with 'nav' in their class
        if (links.size === 0) {
            const navLikeElements = document.querySelectorAll('[class*="nav"]')
            navLikeElements.forEach(element => processLinks(element))
        }

        // Convert Set of JSON strings back to array of objects
        const linksArray = Array.from(links).map(link => JSON.parse(link))
        localStorage.setItem(INTENDR_STORAGE_KEYS.navLinks, JSON.stringify(linksArray))
        return linksArray
      }

      // Function to generate page summary with caching - DISABLED
      async function generatePageSummary() {
        console.log('Page context webhook disabled - generatePageSummary() returns null');
        return null;
      }

      // Function to generate a simple hash of the content
      async function generateContentHash(content) {
        const encoder = new TextEncoder();
        const data = encoder.encode(content);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      }

      // Function to get cached summary
      function getCachedSummary(url, contentHash) {
        try {
          const cached = localStorage.getItem(INTENDR_STORAGE_KEYS.pageSummary);
          if (cached) {
            const { url: cachedUrl, hash: cachedHash, summary, timestamp } = JSON.parse(cached);
            // Check if the cache is for the same URL, content, and less than 1 hour old
            if (cachedUrl === url && cachedHash === contentHash && 
                (Date.now() - timestamp) < 3600000) { // 1 hour cache
              return summary;
            }
          }
        } catch (error) {
          console.error('Error reading cached summary:', error);
        }
        return null;
      }

      // Function to cache summary
      function cacheSummary(url, contentHash, summary) {
        try {
          const cacheData = {
            url,
            hash: contentHash,
            summary,
            timestamp: Date.now()
          };
          localStorage.setItem(INTENDR_STORAGE_KEYS.pageSummary, JSON.stringify(cacheData));
        } catch (error) {
          console.error('Error caching summary:', error);
        }
      }

      // Debounced function to generate summary
      function debouncedGenerateSummary() {
        if (summaryFetchTimeout) {
          clearTimeout(summaryFetchTimeout);
        }
        summaryFetchTimeout = setTimeout(async () => {
          pageSummary = await generatePageSummary();
        }, 1000); // Wait 1 second after last page change before generating summary
      }

      // Generate summary when page loads
      document.addEventListener('DOMContentLoaded', debouncedGenerateSummary);

      // Generate summary when URL changes (for SPA navigation)
      const lastUrl = window.location.href;
      new MutationObserver(() => {
        const currentUrl = window.location.href;
        if (currentUrl !== lastUrl) {
          lastUrl = currentUrl;
          debouncedGenerateSummary();
            }
      }).observe(document, { subtree: true, childList: true });

      // Send message function
      async function sendMessage(message) {
        if (!message.trim()) return;
        
        // Track session start or update
        const messagesContainer = document.querySelector('.chat-messages');
        const userMessages = messagesContainer ? messagesContainer.querySelectorAll('.chat-message.user') : [];
        
        if (userMessages.length === 0) {
          // First message - track session start
          await trackAnalyticsEvent('session_start', {
            firstMessage: message.trim()
          });
        } else {
          // Subsequent messages - track session update
          await trackAnalyticsEvent('session_update', {
            messageCount: userMessages.length + 1,
            userMessageCount: userMessages.length + 1,
            latestMessage: message.trim()
          });
        }
        
        // Execute beforeSendMessage hook if provided
        if (INTENDR_HOOKS.beforeSendMessage && typeof INTENDR_HOOKS.beforeSendMessage === 'function') {
          try {
            const result = await INTENDR_HOOKS.beforeSendMessage(message);
            if (result === false) return; // Hook can cancel message sending
            if (typeof result === 'string') message = result; // Hook can modify message
          } catch (error) {
            console.error('[Intendr] Error in beforeSendMessage hook:', error);
          }
        }
        
        // Add user message to chat
        const userMessageDiv = document.createElement('div');
        userMessageDiv.className = 'chat-message user';
        userMessageDiv.textContent = message;
        messagesContainer.appendChild(userMessageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        
        // Show thinking animation
          // Show thinking animation
          const thinkingDiv = showThinkingAnimation();
          
          try {
          // Page context webhook disabled - using null for pageContext
          const currentPageContext = null;
          
          // Determine if this is the first message of the session
          const isFirstMessage = userMessages.length === 0;
          
          // Prepare message data - only include chat history on first message or when explicitly needed
          const messageData = {
            chatInput: message,
            sessionId: currentSessionId,
            isFirstMessage: isFirstMessage,
            currentPageUrl: window.location.href, // Include current page URL with UTMs
            metadata: {
              business: config.business,
              utmParameters: window.initialUtmParameters || {},
              userIP: userIP,
              currentPageUrl: window.location.href // Also include in metadata for consistency
            }
          };
          
          // Only send chat history on first message or session restoration
          if (isFirstMessage) {
            const chatHistory = getChatHistory();
            if (chatHistory.length > 0) {
              messageData.chatHistory = chatHistory;
              console.log('💬 [Chat Context] First message - sending full conversation history to n8n:', chatHistory);
            } else {
              console.log('🆕 [Chat Context] New session - no previous history to send');
            }
          } else {
            console.log('🔄 [Chat Context] Continuing session - sending only current message and sessionId');
          }
          
          // Send to webhook
            const response = await fetch(config.webhook.url, {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
              },
              body: JSON.stringify(messageData)
            });
            
          if (!response.ok) {
            // Check if it's a session-related error
            const errorText = await response.text();
            if (response.status === 404 || errorText.includes('session') || errorText.includes('unknown')) {
              console.log('🔄 [Chat Context] Session not found in n8n - resending with full history');
              
              // Resend with full chat history
              const chatHistory = getChatHistory();
              messageData.chatHistory = chatHistory;
              messageData.sessionRecovery = true;
              
              const retryResponse = await fetch(config.webhook.url, {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': '*',
                  'Access-Control-Allow-Methods': 'POST, OPTIONS',
                  'Access-Control-Allow-Headers': 'Content-Type'
                },
                body: JSON.stringify(messageData)
              });
              
              if (!retryResponse.ok) throw new Error('Failed to send message after retry');
              response = retryResponse; // Use retry response for processing
            } else {
              throw new Error('Failed to send message: ' + errorText);
            }
          }
          
          // Try to parse as JSON, fallback to plain text
          let botReply = '';
          const responseText = await response.text();
          try {
            const data = JSON.parse(responseText);
            if (Array.isArray(data) && data.length > 0 && data[0].output) {
              botReply = data[0].output;
            } else if (data && typeof data === 'object') {
              botReply = data.output || data.response || data.message || '';
            } else if (typeof data === 'string') {
              botReply = data;
            }
          } catch (e) {
            botReply = responseText;
          }
            // Fallback for empty responses
          if (!botReply || botReply.trim() === '') {
            botReply = "I received your message, but I'm having trouble generating a response.";
            }
            
          // Remove thinking animation
          removeThinkingAnimation();

          // Handle [REDIRECT]...[/REDIRECT] in botReply
          const redirectMatch = botReply.match(/\[REDIRECT\](.*?)\[\/REDIRECT\]/);
          if (redirectMatch && redirectMatch[1]) {
            const originalUrl = redirectMatch[1].trim();
            const redirectUrl = appendUtmToUrl(originalUrl);

            // First, show the message with the redirect URL removed
            const cleanedMessage = botReply.replace(/\[REDIRECT\][\s\S]*?\[\/REDIRECT\]/g, '').trim();
            if (cleanedMessage) {
            const botMessageDiv = document.createElement('div');
            botMessageDiv.className = 'chat-message bot';
              botMessageDiv.innerHTML = formatMessage(cleanedMessage);
            messagesContainer.appendChild(botMessageDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
            
            // Then show 'Redirecting you now...' message
            setTimeout(() => {
              const redirectMsgDiv = document.createElement('div');
              redirectMsgDiv.className = 'chat-message bot';
              redirectMsgDiv.innerHTML = formatMessage('Redirecting you now... If you see anything on this page that interests you, let me know and I will give you more details. ');
              messagesContainer.appendChild(redirectMsgDiv);
              messagesContainer.scrollTop = messagesContainer.scrollHeight;
              
              // Save session before redirecting
            saveSession();
            
              // Redirect after a 3 second delay
              setTimeout(() => {
                window.location.href = redirectUrl;
              }, 3000);
            }, 1000); // Wait 1 second before showing the redirect message
            
            return;
          }

          // Remove any [REDIRECT]...[/REDIRECT] tags from the message if present
          let cleanedReply = botReply.replace(/\[REDIRECT\][\s\S]*?\[\/REDIRECT\]/g, '').trim();

          // Execute customMessageProcessing hook if provided
          if (INTENDR_HOOKS.customMessageProcessing && typeof INTENDR_HOOKS.customMessageProcessing === 'function') {
            try {
              const result = await INTENDR_HOOKS.customMessageProcessing(cleanedReply, botReply);
              if (typeof result === 'string') cleanedReply = result;
            } catch (error) {
              console.error('[Intendr] Error in customMessageProcessing hook:', error);
            }
          }

          // Add bot response (if anything remains after cleaning)
          if (cleanedReply) {
            // Parse action tags and create action buttons
            const processedMessage = parseAndShowActionButtons(cleanedReply);
            
            const botMessageDiv = document.createElement('div');
            botMessageDiv.className = 'chat-message bot';
            botMessageDiv.innerHTML = formatMessage(processedMessage);
            messagesContainer.appendChild(botMessageDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            
            // Execute afterReceiveMessage hook if provided
            if (INTENDR_HOOKS.afterReceiveMessage && typeof INTENDR_HOOKS.afterReceiveMessage === 'function') {
              try {
                await INTENDR_HOOKS.afterReceiveMessage(cleanedReply, botMessageDiv);
              } catch (error) {
                console.error('[Intendr] Error in afterReceiveMessage hook:', error);
              }
            }
          }
            
          // Save session after changes
            saveSession();

          // Reset inactivity timer
          resetInactivityState();
        } catch (error) {
          console.error('Error sending message:', error);
          removeThinkingAnimation();
          
          // Show error message
          const errorMessageDiv = document.createElement('div');
          errorMessageDiv.className = 'chat-message bot';
          errorMessageDiv.innerHTML = formatMessage("I apologize, but I'm having trouble connecting right now. Please try again in a moment.");
          messagesContainer.appendChild(errorMessageDiv);
          messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
      }
      
      // Function to send initial messages
      function sendInitialMessages() {
        const businessName = config.business.name || '[BusinessName]';
        const messages = [
          `${INTENDR_BRANDING.greetingText} I am here to help you with ${businessName}. How can I assist you today?`
        ];

        messages.forEach((message, index) => {
          setTimeout(() => {
            const botMessageDiv = document.createElement('div');
            botMessageDiv.className = 'chat-message bot';
            botMessageDiv.innerHTML = formatMessage(message);
            messagesContainer.appendChild(botMessageDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
          saveSession();
          }, index * 1000); // Send each message with a 1-second delay
        });
      }

      // Overtake modal logic
      function shouldShowOvertake() {
        const pathToMatch = config.overtakePath || '/';
        return config.overtake === true &&
          window.location.pathname === pathToMatch &&
          !localStorage.getItem(INTENDR_STORAGE_KEYS.overtakeShown);
      }

      let overlayDiv = null;
      function showOvertakeModal() {
        overlayDiv = document.createElement('div');
        overlayDiv.className = 'intendr-overtake-overlay';
        overlayDiv.style.position = 'fixed';
        overlayDiv.style.inset = '0';
        overlayDiv.style.background = 'rgba(0,0,0,0.6)';
        overlayDiv.style.zIndex = '2147483646';
        overlayDiv.style.display = 'flex';
        overlayDiv.style.alignItems = 'center';
        overlayDiv.style.justifyContent = 'center';
        overlayDiv.style.transition = 'opacity 0.4s';
        overlayDiv.style.opacity = '0';
        overlayDiv.style.animation = 'intendr-fadein 0.4s forwards';
        chatContainer.classList.add('overtake-modal');
        chatContainer.style.position = 'relative';
        chatContainer.style.left = '';
        chatContainer.style.top = '';
        chatContainer.style.transform = '';
        chatContainer.style.zIndex = '2147483647';
        chatContainer.style.width = '800px';
        chatContainer.style.height = 'auto';
        chatContainer.style.maxHeight = '90vh';
        chatContainer.style.borderRadius = '18px';
        chatContainer.style.boxShadow = '0 8px 32px rgba(0,0,0,0.25)';
        chatContainer.style.opacity = '0';
        chatContainer.style.background = '#fff';
        chatContainer.style.display = 'flex';
        chatContainer.style.flexDirection = 'column';
        chatContainer.style.padding = '32px 28px 20px 28px';
        chatContainer.style.transition = 'opacity 0.4s';
        
        // Ensure CSS variables are set for the overtake modal
        chatContainer.style.setProperty('--chat--color-primary', config.style.primaryColor);
        chatContainer.style.setProperty('--chat--color-secondary', config.style.secondaryColor);
        
        setTimeout(() => { chatContainer.style.opacity = '1'; }, 50);
        if (window.innerWidth <= 900) {
          chatContainer.style.width = '95vw';
        }
          if (window.innerWidth <= 600) {
          chatContainer.style.width = '95vw';
          chatContainer.style.height = '85vh';
          chatContainer.style.maxHeight = '85vh';
          chatContainer.style.borderRadius = '12px';
          chatContainer.style.padding = '16px 6px 10px 6px';
        }
        toggleButton.classList.add('hidden');
        document.body.appendChild(overlayDiv);
        overlayDiv.appendChild(chatContainer);
            document.body.style.overflow = 'hidden';
        localStorage.setItem(INTENDR_STORAGE_KEYS.overtakeShown, '1');
        showChat();
      }

      function hideOvertakeModal() {
        if (overlayDiv) {
          widgetContainer.appendChild(chatContainer);
          overlayDiv.remove();
          overlayDiv = null;
        }
        chatContainer.classList.remove('overtake-modal');
        chatContainer.style.position = '';
        chatContainer.style.left = '';
        chatContainer.style.top = '';
        chatContainer.style.transform = '';
        chatContainer.style.zIndex = '';
        chatContainer.style.width = '';
        chatContainer.style.height = '';
        chatContainer.style.maxHeight = '';
        chatContainer.style.borderRadius = '';
        chatContainer.style.boxShadow = '';
        chatContainer.style.opacity = '';
        chatContainer.style.background = '';
        chatContainer.style.display = '';
        chatContainer.style.flexDirection = '';
        chatContainer.style.padding = '';
        document.body.style.overflow = '';
        hideChat();
          }
          
      // Add fade-in keyframes and modal polish styles
      const modalStyles = document.createElement('style');
      modalStyles.textContent = `
        @keyframes intendr-fadein {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        .intendr-overtake-overlay {
          animation: intendr-fadein 0.4s forwards;
        }
        .overtake-modal .brand-header {
          padding-bottom: 12px;
          border-bottom: 1px solid #f0f0f0;
          margin-bottom: 12px;
        }
        .overtake-modal .brand-header img {
          width: 40px;
          height: 40px;
          margin-right: 10px;
        }
        .overtake-modal .brand-header span {
          font-size: 22px;
          font-weight: 600;
        }
        .overtake-modal .close-button {
          position: absolute;
          right: 18px;
          top: 18px;
          background: none;
          border: none;
          cursor: pointer;
          font-size: 28px;
          color: #888;
          opacity: 0.7;
          z-index: 2;
          transition: opacity 0.2s;
        }
        .overtake-modal .close-button:hover {
          opacity: 1;
        }
        .overtake-modal .chat-messages {
          display: flex;
          flex-direction: column;
          flex: 1 1 0%;
          overflow-y: auto;
          padding: 10px 0 10px 0;
          margin-bottom: 10px;
          background: none;
          min-height: 400px;
        }
        .overtake-modal .chat-input {
          padding: 0;
          border-top: 1px solid #f0f0f0;
          margin-top: 10px;
          background: none;
          display: flex;
          align-items: center;
        }
        .overtake-modal .chat-input textarea {
          flex: 1 !important;
          padding: 12px !important;
          border: 1px solid rgba(133, 79, 255, 0.2) !important;
          border-radius: 8px !important;
          resize: none !important;
          font-family: inherit !important;
          font-size: 14px !important;
          height: auto !important;
          min-height: 40px !important;
          max-height: 120px !important;
          width: auto !important;
          box-sizing: border-box !important;
          margin-right: 8px;
        }
        .overtake-modal .chat-input button[type="submit"] {
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
          color: #fff;
          border: none;
          border-radius: 8px;
          padding: 0 18px;
          cursor: pointer;
          font-weight: 500;
          font-size: 16px;
          height: 40px;
          min-width: 40px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .overtake-modal .chat-input button[type="submit"] svg {
          fill: #fff;
          stroke: #fff;
        }
        .overtake-modal .chat-message.user {
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
          color: #fff;
          align-self: flex-end;
          text-align: right;
          margin-left: auto;
          margin-right: 0;
          box-shadow: 0 4px 12px rgba(133, 79, 255, 0.2);
          border-radius: 12px;
          padding: 12px 16px;
          margin: 8px 0;
          max-width: 80%;
          word-wrap: break-word;
          font-size: 14px;
          line-height: 1.5;
        }
        .overtake-modal #intendr-voice-button {
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
        }
        @media (max-width: 600px) {
          .overtake-modal {
            padding: 0 !important;
          }
          .overtake-modal .brand-header img {
            width: 32px;
            height: 32px;
          }
          .overtake-modal .brand-header span {
            font-size: 18px;
          }
          .overtake-modal .chat-messages {
            min-height: 200px;
          }
        }
        .chat-container.overtake-modal {
          height: 100% !important;
        }
        .chat-interface {
          height: 100%;
          display: flex;
          flex-direction: column;
          justify-content: space-around;
        }
        .overtake-modal {
          height: 60vh;
          max-height: 60vh;
          display: flex;
          flex-direction: column;
        }
        .overtake-modal .chat-messages {
          flex: 1 1 0%;
          overflow-y: auto;
          min-height: 0;
        }
        @media (max-width: 600px) {
          .overtake-modal {
            height: 85vh !important;
            max-height: 85vh !important;
          }
        }
      `;
      document.head.appendChild(modalStyles);
          
      // Add/restore CSS for responsive modal width
      const modalResponsiveStyles = document.createElement('style');
      modalResponsiveStyles.textContent = `
        .overtake-modal {
          width: 800px !important;
          max-width: 95vw;
        }
        @media (max-width: 900px) {
          .overtake-modal {
            width: 95vw !important;
          }
        }
        @media (max-width: 600px) {
          .overtake-modal {
            width: 95vw !important;
            height: 85vh !important;
            max-height: 85vh !important;
            border-radius: 12px !important;
            padding: 16px 6px 10px 6px !important;
          }
        }
      `;
      document.head.appendChild(modalResponsiveStyles);

      // On load, check for overtake
      if (shouldShowOvertake()) {
        setTimeout(() => {
          showOvertakeModal();
        }, 400); // slight delay for effect
      }

      // --- Chat Initialization Refactor ---
      function initChat() {
        // Only run once
        if (window.IntendrChatWidgetChatInitialized) return;
        window.IntendrChatWidgetChatInitialized = true;

        // Restore session or show initial messages
        const sessionRestored = loadSession();
          if (!sessionRestored) {
            inactivityMessageSent = false;
            currentSessionId = generateSessionId();
          sendInitialMessages();
          // Page context webhook disabled - generatePageSummary() removed
          }
          saveSession();
          messagesContainer.scrollTop = messagesContainer.scrollHeight;
          startInactivityTimer();
          clearTimeout(promptBubbleTimer);

        // Add event listeners (only once)
        toggleButton.addEventListener('click', function() {
          showChat();
        });
        closeButton.addEventListener('click', function() {
          // Track session end before closing
          const messagesContainer = document.querySelector('.chat-messages');
          const userMessages = messagesContainer ? messagesContainer.querySelectorAll('.chat-message.user') : [];
          const botMessages = messagesContainer ? messagesContainer.querySelectorAll('.chat-message.bot') : [];
          
          if (userMessages.length > 0) {
            trackAnalyticsEvent('session_end', {
              messageCount: userMessages.length + botMessages.length,
              userMessageCount: userMessages.length,
              botMessageCount: botMessages.length,
              sessionDuration: Date.now() - (new Date().getTime() || Date.now())
            });
          }

          hideChat();
          userManuallyClosedChat = true;
          saveChatState(true);
          if (window.innerWidth <= 600) document.body.style.overflow = '';
        });
        sendButton.addEventListener('click', handleMessageSend);
      textarea.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
            handleMessageSend();
          }
        });
        textarea.addEventListener('input', function() {
          this.style.height = 'auto';
          this.style.height = (this.scrollHeight) + 'px';
        });
        window.addEventListener('resize', function() {
          if (window.innerWidth <= 600) {
            if (chatContainer.classList.contains('open')) document.body.style.overflow = 'hidden';
          } else {
        document.body.style.overflow = '';
          }
        });
      }

      function showChat() {
            hidePromptBubble();
            promptBubbleShown = true;
            chatContainer.classList.add('open');
            toggleButton.classList.add('hidden');
        if (window.innerWidth <= 600) document.body.style.overflow = 'hidden';
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        startInactivityTimer();
        clearTimeout(promptBubbleTimer);
      }

      function hideChat() {
        chatContainer.classList.remove('open');
        toggleButton.classList.remove('hidden');
        if (window.innerWidth <= 600) document.body.style.overflow = '';
      }

      // --- End Chat Initialization Refactor ---

      // Call initChat on page load
      initChat();

      // Page context webhook disabled - generatePageSummary() removed

      // Ensure chat input row markup and send button are correct
      // (Rebuild input row if needed)
      function ensureInputRow() {
        const chatInputDiv = chatContainer.querySelector('.chat-input');
        if (!chatInputDiv) return;
        chatInputDiv.innerHTML = '';
        
        // Voice button with microphone and phone icons
        const voiceBtn = document.createElement('button');
        voiceBtn.type = 'button';
        voiceBtn.title = 'Transfer to Phone';
        voiceBtn.id = 'intendr-voice-button';
        voiceBtn.innerHTML = `
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
          </svg>
        `;
        voiceBtn.style.display = 'flex';
        voiceBtn.style.alignItems = 'center';
        voiceBtn.style.justifyContent = 'center';
        voiceBtn.style.background = 'linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%)';
        voiceBtn.style.color = 'white';
        voiceBtn.style.border = 'none';
        voiceBtn.style.borderRadius = '8px';
        voiceBtn.style.padding = '0 12px';
        voiceBtn.style.cursor = 'pointer';
        voiceBtn.style.fontWeight = '500';
        voiceBtn.style.fontSize = '16px';
        voiceBtn.style.height = '40px';
        voiceBtn.style.minWidth = '40px';
        voiceBtn.style.marginRight = '0';
        
        // Simple phone call initiation
        voiceBtn.onclick = function(e) {
          e.stopPropagation();
          showVoiceTransferModal(); // Use the existing modal for phone calls
        };
        
        // Textarea
        const textareaEl = document.createElement('textarea');
        textareaEl.placeholder = 'Type your message here...';
        textareaEl.rows = 1;
        textareaEl.style.resize = 'none';
        textareaEl.style.flex = '1';
        textareaEl.style.marginRight = '8px';
        textareaEl.className = textarea.className;
        
        // Send button
        const sendBtn = document.createElement('button');
        sendBtn.type = 'submit';
        sendBtn.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>';
        sendBtn.style.display = 'flex';
        sendBtn.style.alignItems = 'center';
        sendBtn.style.justifyContent = 'center';
        sendBtn.style.background = 'linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%)';
        sendBtn.style.color = 'white';
        sendBtn.style.border = 'none';
        sendBtn.style.borderRadius = '8px';
        sendBtn.style.padding = '0 18px';
        sendBtn.style.cursor = 'pointer';
        sendBtn.style.fontWeight = '500';
        sendBtn.style.fontSize = '16px';
        sendBtn.style.height = '40px';
        sendBtn.style.minWidth = '40px';
        
        // Add elements to container
        chatInputDiv.appendChild(voiceBtn);
        chatInputDiv.appendChild(textareaEl);
        chatInputDiv.appendChild(sendBtn);
        
        // Re-attach listeners
        sendBtn.addEventListener('click', handleMessageSend);
        textareaEl.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
            handleMessageSend();
          }
        });
        textareaEl.addEventListener('input', function() {
          this.style.height = 'auto';
          this.style.height = (this.scrollHeight) + 'px';
        });
        
        // Update references
        window.intendrTextarea = textareaEl;
      }
      ensureInputRow();

      // Add/restore CSS for message bubbles and input row
      const bubbleStyles = document.createElement('style');
      bubbleStyles.textContent = `
        .chat-message.user {
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
          color: white;
          align-self: flex-end;
          box-shadow: 0 4px 12px rgba(133, 79, 255, 0.2);
          border-radius: 12px;
          padding: 12px 16px;
          margin: 8px 0;
          max-width: 80%;
          word-wrap: break-word;
          font-size: 14px;
          line-height: 1.5;
        }
        .chat-message.bot {
          background: #ffffff;
          border: 1px solid rgba(133, 79, 255, 0.2);
          color: #333;
          align-self: flex-start;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
          border-radius: 12px;
          padding: 12px 16px;
          margin: 8px 0;
          max-width: 80%;
          word-wrap: break-word;
          font-size: 14px;
          line-height: 1.5;
        }
        .chat-input {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 0;
          border-top: 1px solid #f0f0f0;
          margin-top: 10px;
          background: none;
        }
        .chat-input textarea {
          flex: 1 !important;
          padding: 12px !important;
          border: 1px solid rgba(133, 79, 255, 0.2) !important;
          border-radius: 6px !important;
          resize: none !important;
          font-family: inherit !important;
          font-size: 14px !important;
          height: auto !important;
          min-height: 40px !important;
          max-height: 120px !important;
          width: auto !important;
          box-sizing: border-box !important;
          margin-right: 8px;
        }
        .chat-input button[type="submit"] {
          background: linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%);
          color: white;
          border: none;
          border-radius: 8px;
          padding: 0 18px;
          cursor: pointer;
          font-weight: 500;
          font-size: 16px;
          height: 40px;
          min-width: 40px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
      `;
      document.head.appendChild(bubbleStyles);

      // Add Escape key handler to close modal or minimize chat
      document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
          if (overlayDiv) {
            hideOvertakeModal();
          } else if (chatContainer.classList.contains('open')) {
            hideChat();
          }
        }
      });
      
      // --- Voice Call Integration via n8n ---

      // Helper: Get chat history from localStorage
      function getChatHistory() {
        try {
          const savedSession = localStorage.getItem(INTENDR_STORAGE_KEYS.chatSession);
          if (!savedSession) return [];
          
          const sessionData = JSON.parse(savedSession);
          if (!sessionData.messages || !Array.isArray(sessionData.messages)) return [];
          
          // Format the messages in the structure expected by the API
          return sessionData.messages.map(msg => ({
            role: msg.type === 'user' ? 'user' : 'assistant',
            content: msg.type === 'user' ? msg.content : msg.content.replace(/<[^>]*>/g, ''),
            timestamp: new Date().toISOString()
          }));
        } catch (e) {
          console.error('Failed to parse chat history', e);
          return [];
        }
      }

      // Helper: Get business info from config
      function getBusinessInfo() {
        console.log('Getting business info from config:', config.business);
        // Return the actual business config without fallback values
        return config.business;
      }

      // Helper: Initiate voice call via n8n
      async function initiateVoiceCall(callType, phone) {
        // Execute beforePhoneCall hook if provided
        if (INTENDR_HOOKS.beforePhoneCall && typeof INTENDR_HOOKS.beforePhoneCall === 'function') {
          try {
            const result = await INTENDR_HOOKS.beforePhoneCall(callType, phone);
            if (result === false) return; // Hook can cancel phone call
          } catch (error) {
            console.error('[Intendr] Error in beforePhoneCall hook:', error);
          }
        }
        
        // Get business info directly from config to ensure we have the latest values
        const chatHistory = getChatHistory()
        const businessInfo = config.business
        console.log('[Intendr] Initiating voice call with business info:', businessInfo)
        
        // Extract chatbot ID from webhook URL (between /webhook/ and /chat)
        let chatbotId = '';
        try {
          const webhookUrl = config.webhook.url;
          const matches = webhookUrl.match(/\/webhook\/([^\/]+)/);
          if (matches && matches[1]) {
            chatbotId = matches[1];
            // Remove /chat suffix if present
            chatbotId = chatbotId.replace(/\/chat$/, '');
          }
        } catch (err) {
          console.error('[Intendr] Error extracting chatbot ID:', err);
        }
        
        let payload = {};
        
        if (callType === 'phone_raw') {
          // For direct phone calls, only include the chatbot ID and phone number
          payload = {
            type: callType,
            phone: phone,
            chatbotId: chatbotId,
            businessInfo: businessInfo // Add business info to phone_raw calls
          };
        } else {
          // For regular phone calls from chat, include chat history and session ID
          payload = {
            type: callType,
            chatHistory,
            businessInfo,
            sessionId: currentSessionId,
            chatbotId: chatbotId // Add chatbotId to regular phone calls as well
          };
          
          if (callType === 'phone') {
            if (!phone) throw new Error('Phone number required for phone call');
            payload.phone = phone;
          }
        }
        
        try {
          console.log('[Intendr] Sending voice call payload:', JSON.stringify(payload))
          
          const response = await fetch(INTENDR_API_ENDPOINTS.voiceCall, {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type'
            },
            body: JSON.stringify(payload)
          });
          
          if (!response.ok) {
            const text = await response.text();
            throw new Error('Failed to initiate call: ' + text);
          }
          
          const contentType = response.headers.get('content-type');
          let result;
          if (contentType && contentType.includes('application/json')) {
            result = await response.json();
          } else {
            // Handle text/plain responses
            const text = await response.text();
            result = { 
              status: 'success', 
              message: text,
              callDetails: {
                phone: phone,
                callId: 'unknown',
                status: 'connecting'
              }
            };
          }
          
          // Execute afterPhoneCall hook if provided
          if (INTENDR_HOOKS.afterPhoneCall && typeof INTENDR_HOOKS.afterPhoneCall === 'function') {
            try {
              await INTENDR_HOOKS.afterPhoneCall(callType, phone, result);
            } catch (error) {
              console.error('[Intendr] Error in afterPhoneCall hook:', error);
            }
          }
          
          return result;
        } catch (error) {
          console.error('Error in initiateVoiceCall:', error);
          throw error;
        }
      }



      // Voice Transfer Tooltip (positioned above phone button)
      function showVoiceTransferModal() {
        // Remove any existing tooltip
        const oldTooltip = document.getElementById('intendr-voice-tooltip')
        if (oldTooltip) oldTooltip.remove()
        
        // Find the phone button to position tooltip above it
        const phoneButton = document.getElementById('intendr-voice-button')
        if (!phoneButton) {
          console.error('Phone button not found')
          return
        }
        
        // Get button position
        const buttonRect = phoneButton.getBoundingClientRect()
        
        // Create tooltip container (speech bubble style)
        const tooltip = document.createElement('div')
        tooltip.id = 'intendr-voice-tooltip'
        tooltip.className = 'intendr-widget-overlay'  // Add defensive class
        
        // Apply defensive inline styles to override site CSS
        Object.assign(tooltip.style, {
          position: 'fixed',
          bottom: '130px',
          right: config.style.position === 'left' ? '20px' : '20px',
          background: 'white',
          boxShadow: '0 2px 12px rgba(0,0,0,0.15)',
          borderRadius: '8px',
          padding: '10px',
          zIndex: '2147483646',
          width: '200px',
          boxSizing: 'border-box',
          margin: '0',
          border: 'none',
          outline: 'none',
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
          fontSize: '14px',
          lineHeight: '1.4',
          color: '#333',
          textAlign: 'left'
        })
        
        // Add a CSS pointer to connect tooltip to phone button
        const pointerStyle = document.createElement('style');
        pointerStyle.textContent = `
          #intendr-voice-tooltip::after {
            content: '';
            position: absolute;
            bottom: -10px;
            right: 30px;
            margin-left: -10px;
            border-width: 10px 10px 0;
            border-style: solid;
            border-color: white transparent transparent transparent;
            filter: drop-shadow(0 2px 2px rgba(0,0,0,0.1));
          }
        `;
        document.head.appendChild(pointerStyle);
        
        tooltip.innerHTML = `
          <div style="font-size:1.1rem;font-weight:600;margin-bottom:8px;color:#333;">Prefer to talk on the phone?</div>
          <div style="font-size:0.9rem;color:#666;margin-bottom:12px;">I can ring you now at the number you enter below to make things easier!</div>
          <div id="intendr-phone-input-container" style="width:100% !important;box-sizing:border-box !important;margin:0 !important;padding:0 !important;">
            <input type="tel" id="intendr-direct-phone-input" placeholder="(123) 123-1234" style="width:100% !important;padding:10px !important;border-radius:4px !important;border:1px solid #ccc !important;margin:0 0 6px 0 !important;font-size:1rem !important;box-sizing:border-box !important;font-family:inherit !important;line-height:normal !important;background:white !important;color:#333 !important;outline:none !important;text-align:left !important;">
            <div id="intendr-direct-phone-validation" style="color:#c00 !important;margin:0 0 6px 0 !important;text-align:left !important;display:none !important;font-size:0.85rem !important;font-family:inherit !important;line-height:1.2 !important;padding:0 !important;"></div>
            <button id="intendr-direct-start-call" style="width:100% !important;padding:10px !important;border-radius:4px !important;background:linear-gradient(135deg, var(--chat--color-primary) 0%, var(--chat--color-secondary) 100%) !important;color:#fff !important;font-weight:500 !important;font-size:1rem !important;border:none !important;cursor:pointer !important;box-sizing:border-box !important;box-shadow:0 4px 12px rgba(133, 79, 255, 0.2) !important;font-family:inherit !important;line-height:normal !important;text-align:center !important;margin:0 !important;outline:none !important;">Start Call</button>
          </div>
          <div id="intendr-direct-call-error" style="color:#c00;margin-top:8px;text-align:center;display:none;"></div>
        `;
        
        // Add the tooltip to the body, not as a child of the button
        document.body.appendChild(tooltip);
        
        // Correctly position the tooltip after it's been created
        const phoneRect = phoneButton.getBoundingClientRect();
        const tooltipRect = tooltip.getBoundingClientRect();
        
        // Position tooltip to align the pointer with the center of the phone button
        // Add mobile-specific positioning
        if (window.innerWidth <= 600) {
          tooltip.style.width = '280px';
          tooltip.style.left = '20px';
          tooltip.style.right = 'auto';
          tooltip.style.transform = 'none';
          tooltip.style.bottom = '90px';
          tooltip.style.top = 'auto';
        } else {
          tooltip.style.right = `${window.innerWidth - phoneRect.right - (phoneRect.width / 2) + 30}px`;
        }
        
        // Close tooltip when clicking outside
        document.addEventListener('click', function closeDirectTooltip(e) {
          if (!tooltip.contains(e.target) && e.target !== phoneButton) {
            tooltip.remove();
            document.removeEventListener('click', closeDirectTooltip);
          }
        });
        
        // Add validation functions for direct phone input
        const directPhoneInput = document.getElementById('intendr-direct-phone-input');
        const directValidationDiv = document.getElementById('intendr-direct-phone-validation');
        
        function validateDirectPhoneNumber(phone) {
          const digits = phone.replace(/\D/g, '');
          if (digits.length === 10) {
            return { valid: true, formatted: `+1${digits}` };
          } else if (digits.length === 11 && digits.startsWith('1')) {
            return { valid: true, formatted: `+${digits}` };
          } else {
            return { 
              valid: false, 
              error: 'Please enter a valid US phone number (10 digits)' 
            };
          }
        }
        
        function showDirectValidationError(message) {
          directValidationDiv.textContent = message;
          directValidationDiv.style.display = 'block';
          directPhoneInput.style.borderColor = '#c00';
        }
        
        function clearDirectValidationError() {
          directValidationDiv.style.display = 'none';
          directPhoneInput.style.borderColor = '#ccc';
        }
        
        // Add real-time validation
        directPhoneInput.addEventListener('input', function() {
          const value = this.value.trim();
          if (value) {
            const validation = validateDirectPhoneNumber(value);
            if (validation.valid) {
              clearDirectValidationError();
            } else {
              showDirectValidationError(validation.error);
            }
          } else {
            clearDirectValidationError();
          }
        });
        
        // Handle the call button click
        document.getElementById('intendr-direct-start-call').onclick = async function() {
          const phone = directPhoneInput.value.trim();
          const errorDiv = document.getElementById('intendr-direct-call-error');
          
          // Clear previous errors
          errorDiv.style.display = 'none';
          clearDirectValidationError();
          
          if (!phone) {
            showDirectValidationError('Please enter your phone number.');
            return;
          }
          
          const validation = validateDirectPhoneNumber(phone);
          if (!validation.valid) {
            showDirectValidationError(validation.error);
            return;
          }
          
          try {
            // Disable input while processing
            directPhoneInput.disabled = true;
            document.getElementById('intendr-direct-start-call').disabled = true;
            document.getElementById('intendr-direct-start-call').textContent = 'Connecting...';
            
            // Use formatted phone number with +1
            await initiateVoiceCall('phone_raw', validation.formatted);
            
            // Show success message
            errorDiv.style.color = '#090';
            errorDiv.textContent = 'Call initiated! Please answer your phone.';
            errorDiv.style.display = 'block';
            
            // Remove tooltip after a delay
            setTimeout(() => {
              tooltip.remove();
            }, 3000);
            
          } catch (err) {
            errorDiv.textContent = err.message || "Couldn't connect your call. Please try again.";
            errorDiv.style.display = 'block';
            
            // Re-enable input
            directPhoneInput.disabled = false;
            document.getElementById('intendr-direct-start-call').disabled = false;
            document.getElementById('intendr-direct-start-call').textContent = 'Start Call';
          }
        };
      }



      // Simple voice transfer functionality - removed complex WebSocket voice chat

      // Helper: Extract messages from chat session
      function getChatSessionMessages() {
        try {
          const savedSession = localStorage.getItem(INTENDR_STORAGE_KEYS.chatSession);
          if (!savedSession) return [];
          const sessionData = JSON.parse(savedSession);
          if (!sessionData.messages || !Array.isArray(sessionData.messages)) return [];
          return sessionData.messages.map(msg => ({
            role: msg.type === 'user' ? 'user' : 'assistant',
            content: msg.type === 'user' ? msg.content : msg.content.replace(/<[^>]*>/g, '') 
          }));
        } catch (error) {
          console.error('Error processing chat session messages:', error);
          return [];
        }
      }

    })();

    // Check if localStorage is available and working
    function isLocalStorageAvailable() {
      try {
        const testKey = '__test__';
        localStorage.setItem(testKey, testKey);
        localStorage.removeItem(testKey);
        return true;
      } catch (e) {
        return false;
      }
    }