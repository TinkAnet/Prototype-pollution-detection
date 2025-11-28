'use strict';

// Object

let user = new Object(); // 'object constructor' syntax
let item = {}; // 'Object literal' syntax

user = {
  name: 'John',
  age: 30,
  'likes birds': true
};
console.log(user);
user.isAdmin = true;
delete user.age;
console.log(user);
console.log(user['likes birds']);
let key = 'likes birds';
console.log(user[key]);

console.log(user.name);
console.log(user.age);
console.log(user.key);

// Computed properties
let fruit = "apple";
let bag = {};
bag[fruit] = 5;
bag[fruit +"Computer"] = 10;
console.log(bag);

// Property value shrothand
function makeUser(name, age) {
  return {
    name: name,
    age: age,
  }
}
let person = makeUser("John", 30);
console.log(user.name);

let proto = {
  name: "proto"
};

let obj = {
  for: 1,
  let: 2,
  return: 3,
  0: "test"
};
console.log(obj.for + obj.let + obj.return);

obj.__proto__ = 5; // does nothing. We can't set it to a non-object value
obj.__proto__ = proto;
console.log(obj.__proto__);


// Prperty existence test, "in" operator
let code = {
  language: "js"
};
console.log(code.noSuchProperty === undefined);
console.log("language" in code);

let sample = {
  test: undefined
};
console.log(sample.test);
console.log("test" in sample);

let usr = {
  name: "John",
  age: 30,
  isAdmin: true
}
for (let key in usr) {
  console.log(`key: ${key}, value: ${usr[key]}`);
}


// Are objets ordered?
// integer properties are sorted, others appears in creation order.
//
// The "integer property" term here means a string that can be converted to-and-from an integer without a change.
//
// console.log(String(Math.runc(Number("49")))); // "49", same, integer property
// console.log(String(Math.trunc(Number("+49")))); // "49", not same "+49" not integer property
// console.log(String(Math.trunc(Number("1.2")))); // "1", not same "1.2" not integer property
let codes = {
  "49": "Germany",
  "41": "Switzerland",
  "44": "Great Britain",
  "1": "USA"
};

for (let code in codes) {
  console.log(code);
}

let usr2 = {
  name: "John",
  surname: "Smith"
};
usr2.age = 25;

for (let prop in usr2) {
  console.log(prop);
}

// for (let prop in user) {
//   console.log(prop);
// }

//
// const obj = {
//   foo: 1,
//   propertyIsEnumerable() {
//     return false;
//   },
// };

// Object.defineProperty(obj, 'name', {
//   value: 'hello',
//   writable: false, // throws an error on strict mode.
//   enumerable: true,
// });

// // Normal property addition through assignment creates a properties which show up during property enumeration
// obj.something = 10;

// console.log(obj.propertyIsEnumerable('foo') ? 'true' : 'false');
// console.log(Object.prototype.propertyIsEnumerable.call(obj, 'foo'));

// delete obj.something;

// for (let value in obj) {
//   console.log(value);
// }

// console.log(obj.something);

// // obj.name = 'hello';
