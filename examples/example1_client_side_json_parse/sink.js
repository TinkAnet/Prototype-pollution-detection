/**
 * SINK: Vulnerable merge/extend function
 * This file contains the sink that performs dangerous property copying
 */

// Vulnerable extend function - NO validation
function extend(target, source) {
    for (var key in source) {
        var val = source[key];
        if (target[key] != null && typeof target[key] === 'object' && typeof val === 'object') {
            extend(target[key], val);  // Recursive call
        } else {
            target[key] = val;  // SINK: Property assignment without validation
        }
    }
    return target;
}

// Another vulnerable merge function
function merge(target, source) {
    for (var key in source) {
        if (source.hasOwnProperty(key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) {
                    target[key] = {};
                }
                merge(target[key], source[key]);  // Recursive
            } else {
                target[key] = source[key];  // SINK: No dangerous property check
            }
        }
    }
    return target;
}

// Object.assign usage (also a sink)
function assignConfig(target, config) {
    return Object.assign(target, config);  // SINK: Object.assign
}

