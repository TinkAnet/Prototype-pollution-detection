// This function doesn't have a suspicious name but is still vulnerable
function copyUserSettings(target, source) {
    for (var key in source) {
        target[key] = source[key];  // No validation - vulnerable!
    }
}

// This function is safe
function safeCopyUserSettings(target, source) {
    for (var key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Has validation
        }
        target[key] = source[key];
    }
}

// Another vulnerable function with different pattern
function updateConfig(config, updates) {
    Object.keys(updates).forEach(function(key) {
        config[key] = updates[key];  // No validation!
    });
}

