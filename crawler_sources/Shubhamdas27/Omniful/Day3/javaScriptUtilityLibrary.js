class JavaScriptUtilityLibrary {
    constructor() {
        this.version = '1.0.0';
        this.name = 'JavaScript Utility Library';
    }
    
    // Type checking utilities
    isArray(value) {
        return Array.isArray(value);
    }
    
    isObject(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    }
    
    isFunction(value) {
        return typeof value === 'function';
    }
    
    isString(value) {
        return typeof value === 'string';
    }
    
    isNumber(value) {
        return typeof value === 'number' && !isNaN(value);
    }
    
    isBoolean(value) {
        return typeof value === 'boolean';
    }
    
    isNull(value) {
        return value === null;
    }
    
    isUndefined(value) {
        return value === undefined;
    }
    
    isEmpty(value) {
        if (value === null || value === undefined) return true;
        if (this.isString(value) || this.isArray(value)) return value.length === 0;
        if (this.isObject(value)) return Object.keys(value).length === 0;
        return false;
    }
    
    // Deep merge utility
    deepMerge(target, ...sources) {
        if (!sources.length) return target;
        const source = sources.shift();
        
        if (this.isObject(target) && this.isObject(source)) {
            for (const key in source) {
                if (this.isObject(source[key])) {
                    if (!target[key]) Object.assign(target, { [key]: {} });
                    this.deepMerge(target[key], source[key]);
                } else {
                    Object.assign(target, { [key]: source[key] });
                }
            }
        }
        
        return this.deepMerge(target, ...sources);
    }
    
    // Debounce function
    debounce(func, wait, immediate = false) {
        let timeout;
        
        return function executedFunction(...args) {
            const later = () => {
                timeout = null;
                if (!immediate) func.apply(this, args);
            };
            
            const callNow = immediate && !timeout;
            
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            
            if (callNow) func.apply(this, args);
        };
    }
    
    // Throttle function
    throttle(func, limit) {
        let inThrottle;
        
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
    
    // Deep clone function
    deepClone(obj) {
        if (obj === null || typeof obj !== 'object') return obj;
        if (obj instanceof Date) return new Date(obj.getTime());
        if (Array.isArray(obj)) return obj.map(item => this.deepClone(item));
        
        const clonedObj = {};
        for (let key in obj) {
            if (obj.hasOwnProperty(key)) {
                clonedObj[key] = this.deepClone(obj[key]);
            }
        }
        
        return clonedObj;
    }
    
    // Curry function
    curry(func) {
        return function curried(...args) {
            if (args.length >= func.length) {
                return func.apply(this, args);
            } else {
                return function(...nextArgs) {
                    return curried.apply(this, args.concat(nextArgs));
                };
            }
        };
    }
    
    // Pipe function for function composition
    pipe(...functions) {
        return (value) => functions.reduce((acc, fn) => fn(acc), value);
    }
    
    // Compose function for function composition
    compose(...functions) {
        return (value) => functions.reduceRight((acc, fn) => fn(acc), value);
    }
    
    // Get nested object property safely
    get(obj, path, defaultValue = undefined) {
        const keys = Array.isArray(path) ? path : path.split('.');
        let result = obj;
        
        for (const key of keys) {
            if (result === null || result === undefined || !result.hasOwnProperty(key)) {
                return defaultValue;
            }
            result = result[key];
        }
        
        return result;
    }
    
    // Set nested object property
    set(obj, path, value) {
        const keys = Array.isArray(path) ? path : path.split('.');
        const lastKey = keys.pop();
        let current = obj;
        
        for (const key of keys) {
            if (!current[key] || typeof current[key] !== 'object') {
                current[key] = {};
            }
            current = current[key];
        }
        
        current[lastKey] = value;
        return obj;
    }
    
    // Flatten array
    flatten(arr, depth = Infinity) {
        return depth > 0 ? arr.reduce((acc, val) => 
            acc.concat(Array.isArray(val) ? this.flatten(val, depth - 1) : val), []) : arr.slice();
    }
    
    // Unique array values
    unique(arr) {
        return [...new Set(arr)];
    }
    
    // Chunk array into smaller arrays
    chunk(arr, size) {
        const chunks = [];
        for (let i = 0; i < arr.length; i += size) {
            chunks.push(arr.slice(i, i + size));
        }
        return chunks;
    }
    
    // Random number generator
    random(min = 0, max = 1) {
        return Math.random() * (max - min) + min;
    }
    
    // Random integer generator
    randomInt(min = 0, max = 100) {
        return Math.floor(this.random(min, max + 1));
    }
    
    // Format number with commas
    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }
    
    // Capitalize first letter
    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    }
    
    // Convert string to camelCase
    camelCase(str) {
        return str.replace(/[-_\s]+(.)?/g, (_, char) => char ? char.toUpperCase() : '');
    }
    
    // Convert string to kebab-case
    kebabCase(str) {
        return str.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase().replace(/[_\s]+/g, '-');
    }
    
    // Generate UUID
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    
    // Format bytes
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
    
    // Get library info
    getInfo() {
        return {
            name: this.name,
            version: this.version,
            methods: Object.getOwnPropertyNames(Object.getPrototypeOf(this))
                .filter(name => name !== 'constructor' && typeof this[name] === 'function')
        };
    }
}

// Create default instance
const utils = new JavaScriptUtilityLibrary();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { JavaScriptUtilityLibrary, utils };
}

