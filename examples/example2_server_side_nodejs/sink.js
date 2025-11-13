/**
 * SINK: Server-side vulnerable merge functions
 * These functions perform dangerous property copying
 */

// Vulnerable deep merge function
function deepMerge(target, source) {
    for (var key in source) {
        if (source.hasOwnProperty(key)) {
            var val = source[key];
            if (val != null && typeof val === 'object' && !Array.isArray(val)) {
                if (!target[key] || typeof target[key] !== 'object') {
                    target[key] = {};
                }
                deepMerge(target[key], val);  // Recursive call
            } else {
                target[key] = val;  // SINK: No validation
            }
        }
    }
    return target;
}

// Vulnerable extend function
function extend(target, source) {
    if (!target) target = {};
    for (var key in source) {
        var val = source[key];
        if (target[key] != null && typeof target[key] === 'object' && typeof val === 'object') {
            extend(target[key], val);  // Recursive
        } else {
            target[key] = val;  // SINK: Property assignment
        }
    }
    return target;
}

// Object.assign sink
function mergeConfig(target, source) {
    return Object.assign(target, source);  // SINK: Object.assign
}

module.exports = {
    deepMerge,
    extend,
    mergeConfig
};

