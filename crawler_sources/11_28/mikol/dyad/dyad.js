"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var EventEmitter = require("events");
/**
 * Use `Dyad.getInstance()` for a singleton instance or `new Dyad.Store()` if
 * multiple instances are desired. Then use `store.initialize(...)` to define
 * the store’s initial state.
 */
var Store = /** @class */ (function (_super) {
    __extends(Store, _super);
    function Store() {
        var _this = _super.call(this) || this;
        /**
         * Retrieves the value saved in this store under `key`.
         *
         * @param key - An identifier for a value saved in this store.
         *
         * @returns The value corresponding to `key`.
         */
        _this.get = function (key) {
            return _this._model[key];
        };
        /**
         * Queues `edit` to be saved asynchronously under `key` in this store.
         * If `set()` is called mutlitple times during a single event loop,
         * only the final value will be considered when action is eventually
         * taken; intermediate values resolved by earlier calls to `set()`
         * will be ignored.
         *
         * Each time a final value is determined, it will be compared to the one
         * previously stored under `key`. If the two are different, the final value
         * will be emitted as an event; otherwise no event will be emitted.
         *
         * @param key - The location where the resolved value of `edit` is stored.
         * @param edit - The value to save as `key` or a function, which – given
         *     the previous value of `key` – determines the next value to save.
         *
         * @returns A promise for the value eventually stored under `key`; if multiple
         *     values have been queued, this will be the final value resolved at the
         *     time the queue is culled.
         */
        _this.set = function (key, edit) {
            var model = _this._model;
            var value = model[key];
            var prevValueByKey = _this._prevValueByKey;
            if (!(key in prevValueByKey)) {
                prevValueByKey[key] = value;
            }
            try {
                // Replace any prior value queued in the current event loop.
                model[key] = typeof edit === 'function' ? edit(value) : edit;
                // Trust [spec’d Promise behavior](https://promisesaplus.com/#point-67)
                // to perform further processing asynchronously in next event loop,
                // allowing any subsequent values resolved in the current event loop
                // to replace `model[key]`.
                return Promise.resolve().then(function () {
                    var nextValue = model[key];
                    // The starting value will have been recorded in `prevValueByKey[key]`
                    // during the previous event loop. Clear it and then compare it to the
                    // current value stored under `key`. If the two values are different,
                    // emit a corresponding event.
                    if (key in prevValueByKey) {
                        var prevValue = prevValueByKey[key];
                        delete prevValueByKey[key];
                        if (nextValue !== prevValue) {
                            _this._emittingByKey[key] = true;
                            try {
                                _this.emit(key, nextValue);
                            }
                            finally {
                                _this._emittingByKey[key] = false;
                            }
                        }
                    }
                    return nextValue;
                });
            }
            catch (error) {
                return Promise.reject(error);
            }
        };
        _this.initialize();
        return _this;
    }
    // ---------------------------------------------------------------------------
    // Actions
    /**
     * Triggers a possible state change, passing `action` through middleware
     * registerd via `use()`; then through reducers registered via `bind()`,
     * which may in turn call `set()` to change state.
     *
     * @param action - By default, a plain (preferrably serializable) object
     *     (with a `type` property to determine which reducers will handle it);
     *     middleware may accept additional types of values (for example,
     *     functions or promises) but such values must be transformed before
     *     they can ultimately be dispatched to corresponding reducers.
     *
     * @returns By default, a promise for the `original` action; however,
     *     middleware may resolve to something else (for example, a `cancel()`
     *     function for a deferred action).
     */
    Store.prototype.dispatch = function (action) {
        if (this._isDispatching) {
            throw new Error('Reducers can’t dispatch actions');
        }
        var middleware = this._middleware;
        var self = this;
        var index = -1;
        return (function call(nextIndex, nextAction) {
            if (nextIndex === void 0) { nextIndex = 0; }
            if (nextAction === void 0) { nextAction = action; }
            if (nextIndex <= index) {
                return Promise.reject(new Error('`next()` called more than once'));
            }
            index = nextIndex;
            var nextMiddleware = middleware[nextIndex];
            if (!nextMiddleware) {
                if (!isPlainObject(nextAction)) {
                    return Promise.reject(new Error('`action` is not a plain object'));
                }
                if (!('type' in nextAction)) {
                    return Promise.reject(new Error('`action` doesn’t include a `type` property'));
                }
                var type = nextAction.type;
                var reducers = self._reducersByType[type] || [];
                reducers.forEach(function (reducer) {
                    try {
                        self._isDispatching = true;
                        reducer(self.get, self.set, nextAction);
                    }
                    finally {
                        self._isDispatching = false;
                    }
                });
                return Promise.resolve(nextAction);
            }
            try {
                ++nextIndex;
                return Promise.resolve(nextMiddleware(nextAction, function () { return call(nextIndex, nextAction); }));
            }
            catch (error) {
                return Promise.reject(error);
            }
        }());
    };
    /**
     * Registers one or more reducers to handle corresponding action types.
     *
     * @param actions - A collection of type-reducer pairs.
     *
     * @returns A reference to this store for chaining.
     */
    Store.prototype.bind = function (actions) {
        var _this = this;
        Object.keys(actions).forEach(function (type) {
            if (!_this._reducersByType[type]) {
                _this._reducersByType[type] = [];
            }
            _this._reducersByType[type].push(actions[type]);
        });
        return this;
    };
    // ---------------------------------------------------------------------------
    // Events
    /**
     * Don’t call `emit()` directly; it will be called transitively when a reducer
     * uses `set()` to mutate this store’s state.
     */
    Store.prototype.emit = function (key, nextValue) {
        if (!this._emittingByKey[key]) {
            throw new Error("Can\u2019t emit key '" + key + "' without setting it");
        }
        return _super.prototype.emit.call(this, key, nextValue);
    };
    // ---------------------------------------------------------------------------
    // Middleware
    /**
     * Adds `middleware` to this store; each middleware is given the opportunity,
     * in the order in which it was added to the store, to intercept, inspect, and
     * transform actions before they reach reducers.
     *
     * @param middleware - A function that will be given access to this store’s
     *     pre-reducer dispatch cycle.
     */
    Store.prototype.use = function (middleware) {
        this._middleware.push(middleware);
    };
    // ---------------------------------------------------------------------------
    // Model
    /**
     * Sets (or resets) this store’s initial state.
     *
     * @param model - The desired initial state, if any.
     */
    Store.prototype.initialize = function (model) {
        var _this = this;
        this._emittingByKey = {};
        this._isDispatching = false;
        this._middleware = [];
        this._model = {};
        this._prevValueByKey = {};
        this._reducersByType = {};
        this.removeAllListeners();
        if (model) {
            Object.keys(model).forEach(function (key) { return _this._model[key] = model[key]; });
        }
    };
    /**
     * Generates a list of this store’s keys.
     *
     * @returns This store’s keys ordered as would a normal `for...in` loop.
     */
    Store.prototype.keys = function () {
        return Object.keys(this._model);
    };
    return Store;
}(EventEmitter));
exports.Store = Store;
var store = new Store();
/**
 * Returns the sole instance of `Store`.
 */
function getInstance() {
    return store;
}
exports.getInstance = getInstance;
// -----------------------------------------------------------------------------
function isPlainObject(x) {
    if (x != null && typeof x === 'object') {
        var prototype = Object.getPrototypeOf(x);
        if (prototype === null) {
            return true;
        }
        var nextPrototype 
        // tslint:disable-next-line:no-conditional-assignment
        = void 0;
        // tslint:disable-next-line:no-conditional-assignment
        while ((nextPrototype = Object.getPrototypeOf(prototype)) !== null) {
            prototype = nextPrototype;
        }
        return Object.getPrototypeOf(x) === prototype;
    }
    return false;
}
