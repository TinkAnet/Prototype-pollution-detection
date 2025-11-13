/**
 * MAIN: Connects DOM sources to merge sinks
 */

// Initialize default configuration
var appConfig = {
    theme: 'light',
    language: 'en'
};

// Flow 1: querySelectorAll -> extend sink
var widgetConfigs = getAllWidgetConfigs();  // SOURCE
widgetConfigs.forEach(function(config) {
    extend(appConfig, config);  // SINK: Receives from source
});

// Flow 2: getElementById -> merge sink
var widgetConfig = getConfigById('widget-1');  // SOURCE
if (widgetConfig) {
    merge(appConfig, widgetConfig);  // SINK: Receives from source
}

// Flow 3: querySelector -> deepMerge sink
var widgetData = getWidgetConfig();  // SOURCE
if (widgetData && widgetData.config) {
    deepMerge(appConfig, widgetData.config);  // SINK: Receives from source
}

// Flow 4: Form input -> extend sink
var formInput = getFormInput();  // SOURCE
if (formInput) {
    extend(appConfig, formInput);  // SINK: Receives from source
}

console.log('Final app config:', appConfig);

