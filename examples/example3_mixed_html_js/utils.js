/**
 * UTILS: Source extraction functions
 */

// Source: Extract from dataset
function getConfigFromDataset() {
    var element = document.querySelector('#app-config');
    if (element && element.dataset.settings) {
        return JSON.parse(element.dataset.settings);  // SOURCE: JSON.parse from dataset
    }
    return null;
}

// Source: Extract from multiple attributes
function getAllConfigs() {
    var element = document.querySelector('#app-config');
    var configs = {};
    
    if (element) {
        // Source: getAttribute
        var settings = element.getAttribute('data-settings');
        if (settings) {
            configs.settings = JSON.parse(settings);  // SOURCE
        }
        
        // Source: dataset
        var options = element.getAttribute('data-options');
        if (options) {
            configs.options = JSON.parse(options);  // SOURCE
        }
    }
    
    return configs;
}

// Source: QuerySelector + getAttribute chain
function getConfigFromQuery() {
    var element = document.querySelector('[data-settings]');  // SOURCE: querySelector
    if (element) {
        return JSON.parse(element.getAttribute('data-settings'));  // SOURCE: getAttribute + JSON.parse
    }
    return null;
}

