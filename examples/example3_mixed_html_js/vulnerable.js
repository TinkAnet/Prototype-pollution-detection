/**
 * SINK: Vulnerable merge functions
 */

// Vulnerable recursive merge
function extend(target, source) {
    if (!target) target = {};
    for (var key in source) {
        var val = source[key];
        if (target[key] != null && typeof target[key] === 'object' && typeof val === 'object' && !Array.isArray(val)) {
            extend(target[key], val);  // Recursive
        } else {
            target[key] = val;  // SINK: No validation
        }
    }
    return target;
}

// Vulnerable deep copy
function deepCopy(target, source) {
    for (var key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) {
                target[key] = {};
            }
            deepCopy(target[key], source[key]);  // Recursive
        } else {
            target[key] = source[key];  // SINK: Property assignment
        }
    }
    return target;
}

// Object.assign sink
function merge(target, source) {
    return Object.assign({}, target, source);  // SINK: Object.assign
}

