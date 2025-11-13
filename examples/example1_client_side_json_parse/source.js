/**
 * SOURCE: JSON.parse from DOM attribute
 * This file contains the source of user-controlled data
 */

// Source 1: JSON.parse from getAttribute
function getConfigFromDOM() {
    var element = document.querySelector('#config');
    var configStr = element.getAttribute('data-config');
    var config = JSON.parse(configStr);  // SOURCE: JSON.parse
    return config;
}

// Source 2: JSON.parse from localStorage
function getConfigFromStorage() {
    var stored = localStorage.getItem('user-config');
    if (stored) {
        return JSON.parse(stored);  // SOURCE: JSON.parse
    }
    return null;
}

// Source 3: JSON.parse from URL parameter
function getConfigFromURL() {
    var params = new URLSearchParams(window.location.search);
    var configParam = params.get('config');
    if (configParam) {
        return JSON.parse(decodeURIComponent(configParam));  // SOURCE: JSON.parse
    }
    return null;
}

