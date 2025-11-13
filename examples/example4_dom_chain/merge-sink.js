/**
 * SINK: Vulnerable merge operations
 */

// Vulnerable extend with for...in loop
function extend(target, source) {
    for (var key in source) {
        var val = source[key];
        if (target[key] != null && typeof target[key] === 'object' && typeof val === 'object') {
            extend(target[key], val);  // Recursive
        } else {
            target[key] = val;  // SINK: Computed property assignment
        }
    }
    return target;
}

// Vulnerable merge with Object.assign
function merge(target, ...sources) {
    var result = target || {};
    for (var i = 0; i < sources.length; i++) {
        result = Object.assign(result, sources[i]);  // SINK: Object.assign
    }
    return result;
}

// Vulnerable deep merge
function deepMerge(target, source) {
    if (!target) target = {};
    for (var key in source) {
        if (source.hasOwnProperty(key)) {
            var val = source[key];
            if (val != null && typeof val === 'object' && !Array.isArray(val)) {
                if (!target[key] || typeof target[key] !== 'object') {
                    target[key] = {};
                }
                deepMerge(target[key], val);  // Recursive
            } else {
                target[key] = val;  // SINK: Property assignment
            }
        }
    }
    return target;
}

