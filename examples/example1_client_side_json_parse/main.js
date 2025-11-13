/**
 * MAIN: Connects source to sink
 * This demonstrates data flow from source to sink
 */

// Data flow: source -> sink
var defaultConfig = { theme: 'light' };
var userConfig = getConfigFromDOM();  // SOURCE

// SINK: extend function receives data from source
extend(defaultConfig, userConfig);

// Another flow
var storageConfig = getConfigFromStorage();  // SOURCE
if (storageConfig) {
    merge(defaultConfig, storageConfig);  // SINK
}

// Object.assign sink
var urlConfig = getConfigFromURL();  // SOURCE
if (urlConfig) {
    assignConfig(defaultConfig, urlConfig);  // SINK
}

console.log('Config loaded:', defaultConfig);

