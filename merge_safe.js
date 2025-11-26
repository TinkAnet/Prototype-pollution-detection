// Safe merge function - WITH prototype pollution protection
function merge(target, source) {
    for (let key in source) {
        // Protection: Skip __proto__, constructor, and prototype
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        
        if (source.hasOwnProperty(key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) {
                    target[key] = {};
                }
                merge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}

module.exports = merge;

