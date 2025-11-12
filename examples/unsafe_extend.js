/**
 * Example of unsafe extend function that doesn't check for dangerous properties
 * This is vulnerable to prototype pollution attacks
 */

// Unsafe extend function (similar to pace-js vulnerability)
function extend() {
    var key, out, source, sources, val, _i, _len;
    out = arguments[0], sources = 2 <= arguments.length ? Array.prototype.slice.call(arguments, 1) : [];
    for (_i = 0, _len = sources.length; _i < _len; _i++) {
        source = sources[_i];
        if (source) {
            for (key in source) {
                if (!source.hasOwnProperty(key)) continue;
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

// Example usage that could be exploited
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
        return JSON.parse(data);  // This could parse malicious JSON
    } catch (_error) {
        e = _error;
        return typeof console !== "undefined" && console !== null ? console.error("Error parsing inline pace options", e) : void 0;
    }
}

// Vulnerable code that merges options
var defaultOptions = {
    ajax: false,
    document: true,
    eventLag: false,
    elements: {
        checkInterval: 100,
        selectors: ["body"]
    }
};

// This is vulnerable - parsed JSON from DOM is merged without validation
var options = extend({}, defaultOptions, window.paceOptions, getFromDOM());

// Direct dangerous property assignment (also vulnerable)
var obj = {};
obj.__proto__.polluted = "test";

