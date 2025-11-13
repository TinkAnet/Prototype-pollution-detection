/**
 * SOURCE: DOM attribute extraction
 * Demonstrates various DOM source patterns
 */

// Source 1: querySelectorAll + getAttribute
function getAllWidgetConfigs() {
    var widgets = document.querySelectorAll('.widget');  // SOURCE: querySelectorAll
    var configs = [];
    
    for (var i = 0; i < widgets.length; i++) {
        var configAttr = widgets[i].getAttribute('data-config');  // SOURCE: getAttribute
        if (configAttr) {
            configs.push(JSON.parse(configAttr));  // SOURCE: JSON.parse
        }
    }
    
    return configs;
}

// Source 2: getElementById + dataset
function getConfigById(id) {
    var element = document.getElementById(id);  // SOURCE: getElementById
    if (element && element.dataset.config) {
        return JSON.parse(element.dataset.config);  // SOURCE: dataset + JSON.parse
    }
    return null;
}

// Source 3: querySelector + multiple attributes
function getWidgetConfig() {
    var widget = document.querySelector('.widget');  // SOURCE: querySelector
    if (widget) {
        var config = widget.getAttribute('data-config');  // SOURCE: getAttribute
        var options = widget.getAttribute('data-options');  // SOURCE: getAttribute
        
        return {
            config: config ? JSON.parse(config) : null,  // SOURCE: JSON.parse
            options: options ? JSON.parse(options) : null  // SOURCE: JSON.parse
        };
    }
    return null;
}

// Source 4: Form input value
function getFormInput() {
    var input = document.querySelector('input[type="text"]');
    if (input && input.value) {
        return JSON.parse(input.value);  // SOURCE: JSON.parse from input.value
    }
    return null;
}

