// 16-21 April 2022
// prototype pollution in JavaScript - sources, detection, defenses

// [ draft in progress... ]

// Every object has this property: __proto__.
// The __proto__ property has been deprecated officially since 2015 but is still supported everywhere.
// The __proto__ property points to the object's constructor's prototype property.
// Every prototype is a property of a constructor function
// For example, `"a string".constructor.prototype` is `String.prototype` which inherits from `Object.prototype` and contains a few of its own properties.
// Every value has or can be "promoted/coerced/re-cast" to an object that has a constructor with a prototype property.
// Every object or array you create by literal syntax ({}) or construction syntax (Object() or new Object()) contains this __proto__ property, which defaults to Object.prototype.

// Prototype pollution or poisoning refers to users adding properties to the __proto__ property or to the objecty's constructor's prototype. 
// Any object that inherits from that prototype is said to be extended if we intend this behavior, or polluted if we do not.
// Of all articles on the pollution problem, Bryan English covered it best in 2018, [JavaScript Prototype Poisoning Vulnerabilities in the Wild](https://medium.com/intrinsic-blog/javascript-prototype-poisoning-vulnerabilities-in-the-wild-7bc15347c96).

// Another way to say all this.
// You can extend any object by amending its prototype. We call this *inheritance* when we intend this behavior, or *pollution* when we do not.

// Different ways to create this problem

// Starting with prototype-based inheritance in JavaScript, we can define a
// custom "__proto__" property on an object:

var p = {
  "__proto__": {
    "name": "p",
    "toString": function() { return this.name + " is customized" }
  }
};

console.log(
  p.toString()
);
// p is customized

console.log(
  p.__proto__.toString()
);
// p is customized

console.log(
  p.name === p.__proto__.name,
  p.toString === p.__proto__.toString
);
// true

// What's interesting about this first example is that "__proto__" is
// defined as an instance property on the object, but once JavaScript
// assigns the object to the variable, "__proto__" is absorbed into 
// the object's inheritance chain.

console.log(
  p.hasOwnProperty("__proto__") // !!!
);
// false

// Why is that?
// Because that property is a defined as a *setter* on Object.prototype, rather than as a *writable* value.

Object.getOwnPropertyDescriptor( Object.prototype, "__proto__" );
/*
Object { 
  get: __proto__(),
  set: __proto__(),
  enumerable: false,
  configurable: true
  <prototype>: Object { … }
}
*/

// And while the value is configurable (deletable), if we try removing it with the `delete` keyword,

delete p.__proto__;
// true

// ...it's not removed:

console.log(p.__proto__);
// Object { name: "p", toString: toString() }

// Can we re-define it to `undefined`...?

p.__proto__ = undefined;

// Not directly.
console.log(p.__proto__);
// Object { name: "p", toString: toString() }

// 17 April 2022
// We can re-define it to `undefined` by *assigning* its value to `null`!

p.__proto__ = null;
console.log(p.__proto__);
// undefined

// Well, it turns out we can assign only objects or null to the __proto__ property. Any other value assignment fails silently.

// 21 April 2022
// But wait! Functions are objects, too.

var a = {};
a.__proto__ = function() {
  console.log("__proto__ called")
}
a.__proto__()
// "__proto__ called"

// inherited
var b = Object.create(a)
b.__proto__.__proto__()
// "__proto__ called"

// What about assigning it to Object.create(null)?

var a = {};
a.__proto__ = Object.create(null)

console.log(a.__proto__)
// undefined

// And that means the other properties are no longer inherited.

a.hasOwnProperty("__proto__")
// TypeError: a.hasOwnProperty is not a function

// You cannot delete the prototype of the Object constructor because it is writable, or deletable:

Object.getOwnPropertyDescriptor(Object, "prototype");
/*
Object {
  configurable: false
  enumerable: false
  value: Object { … }
  writable: false
  <prototype>: Object { … }
}
*/


// What happens if we try to merge that object into another using Object.assign()? 

var o = Object.assign({},  p);
console.log(o.name);
// undefined

// Object.assign() ignores the __proto__ key in this case because *__proto__ is not an instance key in this case*.

// One other thing we can check is whether p's __proto__ property is the same as its constructor's prototype.

// Restoring p to the opening definition:

p = {
  "__proto__": {
    "name": "p",
    "toString": function() { return this.name + " is customized" }
  }
}

// Test
console.log( p.__proto__ == p.constructor.prototype );
// false

// But we *can* "restore" p's __proto__ field to its constructor's prototype:

p.__proto__ = p.constructor.prototype


// This suggests there are two different data cleaning cases:
// - instance cleaning
// - prototype chain cleaning
// Plus the option to remove or ignore certain keys from being inherited.


// __proto__ property assigned via JSON.parse()

var op = JSON.parse('{ "__proto__": { "admin": "pwned" } }');
var p = Object.assign({}, op);

console.log( p.admin )
// "pwned"

console.log(
  op.hasOwnProperty("__proto__"),
  p.hasOwnProperty("__proto__")
)
// true false

// __proto__ property defined via Object.defineProperty

var oq = Object.defineProperty({}, '__proto__', {
  value: { "admin": "defpwned" },
  enumerable: true,
  configurable: false,
  writable: false
});
var q = Object.assign({}, oq);

console.log( q.admin )
// "defpwned"

console.log(
  oq.hasOwnProperty("__proto__"),
  q.hasOwnProperty("__proto__")
)
// true false


// constructor property defined via Object.defineProperty

var or = Object.defineProperty({}, 'constructor', {
  value: function(_) {
    console.log(_); 
    this.admin = "admin";
    // Even sneakier: set admin on the prototype
    'admin' in this.__proto__ || (this.__proto__.admin = "admin");
  },
  enumerable: true,
  configurable: false,
  writable: false
});
var r = new (Object.assign({}, or)).constructor("constructed");
// "constructed"

console.log( r.admin )
// "admin"

console.log( r.__proto__.admin )
// "admin"

console.log(
  or.hasOwnProperty("constructor"),
  r.hasOwnProperty("constructor")
)
// true false


// Property path setting (underscore, lodash)
// setting constructor.prototype.pwned on an object
// using a deep property setter such as this:

var set = function(obj, path, value) {
  var o = obj;
  
  path.split(".").forEach(function(name, i, a) {
    o.hasOwnProperty(name) || (o[name] = {});
    
    i == a.length - 1
      ? o[name] = value
      : o = o[name];
  });
  
  return obj;
}

set({}, 'a.b.c.d', "five");
// Object { a: { b: { c: { d: "five" } } } }

// You can pollute the object's constructor's prototype by name:

set({}, 'constructor.prototype.pwned', "oh yeah");
// { constructor: { prototype: { pwned: "oh yeah" } } }

console.log(
  ({}).constructor.prototype,
  Object.prototype
);
// Object { pwned: "oh yeah", … } Object { pwned: "oh yeah", … }

// And you can set the __proto__ property of an object, which has the same effect.

var A = set({}, '__proto__.pwned', true);

console.log(
  A.__proto__.pwned
);
// true

console.log( Object.prototype.pwned );
// true





// What normal property access looks like.

// Object instances normally have no "own" or instance properties, unless the constructor creates `this.field = value` assignments.

console.log(
  r.hasOwnProperty("constructor"),
  q.hasOwnProperty("__proto__"),
  p.hasOwnProperty("__proto__")
);
// false false false

console.warn(
  or.hasOwnProperty("constructor"),
  oq.hasOwnProperty("__proto__"),
  op.hasOwnProperty("__proto__")
);
// true true true



// Elaborate base prototype

var p = {
  constructor: function() {},
  Admin: true,
  toString: function() { return "" + this.valueOf() },
  valueOf: function() { return "pwned" }
};

var A = (function(_) {
  var F = _.constructor;
  Object.assign(F.prototype, _);
  return F
})(p);

var a = new A;
a.Admin
// true
a + ""
// "pwned"
a.valueOf()
// "pwned"

console.log(
  a.hasOwnProperty("constructor"),
  a.hasOwnProperty("__proto__"),
  a.hasOwnProperty("toString"),
  a.hasOwnProperty("valueOf"),
  a.Admin, // !!
  a.toString()
)
// false false false false "pwned" "pwned"

console.log(
  a.__proto__.hasOwnProperty("toString"),
  a.__proto__.hasOwnProperty("valueOf"),
  a.constructor.hasOwnProperty("prototype"),
  a.constructor.prototype === p.__proto__
)
// true true true true


// Mitigations


// Object.create(null) creates an object without a prototype, meaning it has no constructor, toString, or valueof methods, nor a __proto__ property.

var obj = Object.create(null);

console.log(
  obj.__proto__,
  obj.constructor,
  obj.toString,
  obj.valueof,
)

// undefined undefined undefined undefined


// Deletion

// The Object.prototype typically has only inherited properties, no "own" or instance properties.

// Any time you create an object using the literal notation, {}, you should not see any property names on it:

Object.getOwnPropertyNames({ /* bare object */ }).forEach(key => {
  console.log( key );
})

// But when someone in your codebase does this:

Object.prototype.pwned = true;

// ...then
// 1. you'll see "pwned" in the console, and 
// 2. you have to remove it from the Object.prototype yourself.

// You can do that with this cleanup step using Object.keys() which iterates over the enumerable instance properties... 

Object.keys(Object.prototype).forEach(key => {
  console.log( key )
  delete Object.prototype[ key ]
});
// pwned


// Filter unwanted properties from JSON strings when parsing.

var s = '{"__proto__": { "pwned": true }}';

JSON.parse(s, function(k, v) {
  console.log(k)
})
// pwned
// __proto__
// <empty string>

var p = JSON.parse(s, function(k, v) {
  return k == '__proto__' ? undefined : v
});

console.log( p.pwned )
// undefined


// When merging a suspect object where __proto__ *may* be an instance property, use Object.keys(o).forEach():

var s = '{"__proto__": { "pwned": true }}';
var o = JSON.parse(s)
console.log( o );
// {
//  __proto__: Object { pwned: true }
// }

var p = {};
Object.keys(o).forEach(function(k) {
  k != '__proto__' && (p[k] = o[k]);
});
console.log( p );
// { }


// What about Object.freeze()?

// Use that only on constructor/class prototypes that you control.

// If we shouldn't modify built-in prototypes by adding properties, we shouldn't modify their existing property access either.
