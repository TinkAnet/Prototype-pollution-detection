/**
 * Example of SAFE extend function that checks for dangerous properties
 * This is the patched version that prevents prototype pollution
 */

// Safe extend function with property validation
function extend() {
    var key, out, source, sources, val, _i, _len;
    out = arguments[0], sources = 2 <= arguments.length ? Array.prototype.slice.call(arguments, 1) : [];
    
    // Dangerous properties that should be blocked
    var dangerousProperties = ['__proto__', 'constructor', 'prototype'];
    
    for (_i = 0, _len = sources.length; _i < _len; _i++) {
        source = sources[_i];
        if (source) {
            for (key in source) {
                // Check for dangerous properties
                if (!source.hasOwnProperty(key) || dangerousProperties.indexOf(key) !== -1) continue;
                
                val = source[key];
                if ((out[key] != null) && typeof out[key] === 'object' && (val != null) && typeof val === 'object') {
                    extend(out[key], val);
                } else {
                    out[key] = val;
                }
            }
        }
    }
    return out;
}

// Safe usage with validation
function getFromDOM(key, json) {
    var data, e, el;
    if (key == null) {
        key = 'options';
    }
    if (json == null) {
        json = true;
    }
    el = document.querySelector("[data-pace-" + key + "]");
    if (!el) {
        return;
    }
    data = el.getAttribute("data-pace-" + key);
    if (!json) {
        return data;
    }
    try {
        var parsed = JSON.parse(data);
        // Validate parsed data before returning
        if (parsed && typeof parsed === 'object') {
            // Remove dangerous properties
            delete parsed.__proto__;
            delete parsed.constructor;
            delete parsed.prototype;
        }
        return parsed;
    } catch (_error) {
        e = _error;
        return typeof console !== "undefined" && console !== null ? console.error("Error parsing inline pace options", e) : void 0;
    }
}

