(function() {  
    // utility functions
    function isFunction(fn) {
        return typeof fn === 'function';
    }
    function extend(target,sources) {
        sources = sources && Array.prototype.slice.call(arguments,1) || [];
        for (var i = 0, len = sources.length; i < len; i++) {
            var s = sources[i];
            for(var key in s) {
                target[key] = s[key];
            }
        }
        return target;
    }

    // Crockford's object function, returns a new object that inherits from o
    function object(o) {
        function F() {}
        F.prototype = o;
        return new F();
    }  
    function protoCreate(superClass,methods) {
        return Class.create(superClass,methods);
    }
    function simpleCreate(superClass,methods) {
        return (superClass || Class || Base).extend(methods);
    }
    // poor-man's classical inheritance (no $super/_super)
    function newClass(superClass,methods) {
        function f() {  
            if(isFunction(this.init)) {
                this.init.apply(this,arguments); 
            }
        }
        f.prototype = extend(superClass ? object(superClass.prototype) : {}, methods);    
        return f;
    }
    var createClass = window.Class && (
            isFunction(Class.create) && protoCreate  || // Prototype JS is available (should also catch MooTools)
            isFunction(Class.extend) && simpleCreate    // Simple JavaScript Inheritance is available
        ) || window.Base && isFunction(Base.extend) && simpleCreate || // base2 is available
        newClass;                                // none of the above, use poor-man's implementation

    /**
     * Implements classical or prototypal inheritance, depending on what is passed. If a class is passed,
     * a new class that inherits from it will be returned. If an object is passed, a new object that inherits
     * from it will be returned.
     *
     * @param {Function Object} sup the thing to inherit from. Either a class (function) or an object. If
     * null is passed (must be null, not 0, undefined or ''), a class with no supertype is created.
     * @param {Object} [props] optional methods and properties to add to the object/class.
     * @return {Function Object}
     */
    function isA(sup, props) {
        return isFunction(sup) || sup === null ? 
            createClass(sup,props||{}) : extend(object(sup),props);
    }
  
    /**
     * Creates a class with no supertype. Equivalent to isA(null,proto), but
     * more readable.
     * 
     * @param {Object} [proto] properties to copy to the prototype.
     */
    isA.Class = function(proto) {
        return createClass(null,proto || {});
    };
    
    var oldIsA = window.isA;  
    function noConflict() {
        if(typeof oldIsA === "undefined") {
            delete window.isA;
        } else {
            window.isA = oldIsA;
        }
        return isA;
    }
    /**
     * Restore the value of window.isA to whatever it was before.
     * @return {Function} isA
     */
    isA.noConflict = noConflict;
    
    window.isA = isA;
})();