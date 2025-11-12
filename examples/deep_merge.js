// Deep merge function - vulnerable
function deepMerge(target, source) {
    for (var key in source) {
        if (source.hasOwnProperty(key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (typeof target[key] === 'object' && target[key] !== null) {
                    deepMerge(target[key], source[key]);  // Recursive - no __proto__ check!
                } else {
                    target[key] = source[key];
                }
            } else {
                target[key] = source[key];
            }
        }
    }
}

// Safe deep merge - validates dangerous properties
function safeDeepMerge(target, source) {
    for (var key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip dangerous properties
        }
        if (source.hasOwnProperty(key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (typeof target[key] === 'object' && target[key] !== null) {
                    safeDeepMerge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            } else {
                target[key] = source[key];
            }
        }
    }
}

