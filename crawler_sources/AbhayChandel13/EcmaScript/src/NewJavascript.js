// Write a function to find the nth Fibonacci number.

//The Fibonacci series is a sequence of numbers in which each number (Fibonacci Nuumber) is the sum tof two preceding ones. It starts with 0 and 1, and the sunbsequent numbers are calculated by adding the last two numbers. So, the Fibonacci series looks like this: 0,1,1,2,3,5,8,13,21, .......

//todo syntax: F(n)= F(n-1)+ F(n-2), Where, F(1) = F(2) = 1.

const fibonacci = (num) => {
  if (num <= 1) {
    return num;
  } else {
    return fibonacci(num - 1) + fibonacci(num - 2);
  }
};

console.log(fibonacci(0));
console.log(fibonacci(1));
console.log(fibonacci(2));
console.log(fibonacci(3));
console.log(fibonacci(4));
console.log(fibonacci(5));

console.log("====================================================");

// star pattern Upper pyramid:
let n = 5;
for (let i = 1; i <= n; i++) {
  let str = "* ";
  let space = "  ";
  console.log(space.repeat(n - i) + str.repeat(i * 2 - 1));
}

console.log("====================================================");
// Inverted star pattern pyramid:
let m = 5;
for (let i = 5; i >= 1; i--) {
  let str = "* ";
  let space = "  ";
  console.log(space.repeat(m - i) + str.repeat(i * 2 - 1));
}

console.log("====================================================");
//funtction to convert array into a string :

// Original Array
let courses = ["HTML", "CSS", "JavaScript", "React"];

// Converting array to String
let str = courses.toString();
console.log("Coverting array to string:");
console.log(str);

// Original Array
let learn = ["HTML", "CSS", "JavaScript", "React", "Next.Js"];

// Joining the array elements
console.log("Joining the array elements by an element:");
console.log(learn.join("||"));

const fruits = ["Banana", "Orange", "Apple", "Mango"];
let size = fruits.length;
// array length syntax: fruits.length (where fruits is array);
console.log(size);

let simple = fruits.toString();
// array to string syntax: fruits.toString() (where fruits is array);
console.log(simple);

//Multiply an array by 2
let arr = [1, 2, 3];
let newArr = arr.map((x) => x * 2); // newArr is [2, 4, 6]
console.log("newArr :", newArr);

//Index of array from last.
let arr1 = [1, 2, 3, 2, 3, 7];
arr1.lastIndexOf(2); // returns 3
console.log("arr1 :", arr1);

//Index of array
let arr2 = [1, 2, 3, 4, 5];
arr2.indexOf(2); // returns 1

console.log("arr2 :", arr2);

//Flatten an array:
const flattenArray = (arr) => arr.flat(Infinity);

console.log("FlatenArray e.g.=", flattenArray([1, [2, [3, [4]], 5]])); // [1, 2, 3, 4, 5]

//Select unique elements from an array:
const uniqueElements = (arr) => [...new Set(arr)];

console.log(
  "Unique Array Elements e.g.=",
  uniqueElements([1, 2, 2, 3, 4, 4, 5, 6, 6, 6])
); // [1, 2, 3, 4, 5]

//array debounce(settimeout) function:
const debounce = (fn, delay) => {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), delay);
  };
};

// Example usage:
const logMessage = (message) => console.log(message);
const debouncedLogMessage = debounce(logMessage, 2000);

debouncedLogMessage("Hello, world!");
// This will log "Hello, world!" after 2 seconds if not called again within that time.

const numbers = [1, 2, 3, 4];
const doubled = numbers.map((num) => num * 2);
console.log(doubled); // [2, 4, 6, 8]

const numbers2 = [1, 2, 3, 4, 5, 6];
const evenNumbers = numbers2.filter((num) => num % 2 === 0);
console.log(evenNumbers); // [2, 4, 6]

// ============================================================

function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] instanceof Object && target[key] instanceof Object) {
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Explanation:

// deepMerge iterates through the source object’s properties.
// If a property is an object in both target and source, it recursively merges them.
// Otherwise, it simply assigns the source property to target.
// Usage Example:
const obj1 = { a: 1, b: { c: 2, d: 3 } };
const obj2 = { b: { d: 4, e: 5 }, f: 6 };
const merged = deepMerge(obj1, obj2);
console.log("Deepmerged function output: ", merged);

// Output: { a: 1, b: { c: 2, d: 4, e: 5 }, f: 6 }

function curry(fn) {
  return function curried(...args) {
    if (args.length >= fn.length) {
      return fn(...args);
    }
    return (...next) => curried(...args, ...next);
  };
}

// Explanation:

// curry transforms a function into a curried version that takes arguments one at a time.
// It checks if enough arguments have been provided; if so, it calls the original function.
// Otherwise, it returns a new function that collects more arguments.

// Usage Example:
const add = (a, b, c) => a + b + c;
const curriedAdd = curry(add);
console.log(curriedAdd(1)(2)(3)); // Output: 6

const randomString = (length) => {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from(
    { length },
    () => chars[Math.floor(Math.random() * chars.length)]
  ).join("");
};

console.log("Random String:", randomString(10)); // Example: 'aB3dE5gH7k'
console.log("Random String:", randomString(5)); //Example: 'shdej'
console.log("Random String:", randomString(7));
console.log("Random String:", randomString(4));

// ------------------------

function capitalizeWords(str) {
  return str.replace(/\b\w/g, (char) => char.toUpperCase());
}

// Example usage
const sentence = "hello india javascript code is here";
const capitalized = capitalizeWords(sentence);
console.log(capitalized); // Output: "Hello World From Javascript"

// ------------------------

function shuffleArray(array) {
  return array.sort(() => Math.random() - 0.5);
}

// Example usage
const numbersarr = [1, 2, 3, 4, 5];
const shuffled = shuffleArray(numbersarr);
console.log("Shuffled Array: ", shuffled); // Output: A shuffled array, e.g., [3, 5, 1, 2, 4]

//This trick is particularly useful when dealing with API responses or functions that accept configuration objects, ensuring that your code can handle missing or undefined properties gracefully.

// Object destructuring with default values
const user = {
  Username: "Alice",
  age: 25,
  // city is missing
};

const { Username, age, city = "Unknown" } = user;
console.log(Username); // Output: "Alice"
console.log(age); // Output: 25
console.log(city); // Output: "Unknown"

// -------------------------------
//These tricks are widely used in modern JavaScript development and can significantly improve code readability and efficiency.

// Example of short-circuit evaluation
const isLoggedIn = false;
const userRole = isLoggedIn && "admin";
console.log(userRole); // Output: "admin"

// Fallback with OR operator
const port = process.env.PORT || 3000;
console.log(port); // Output: 5000 (if process.env.PORT is undefined)
console.log(port); //output:3000 
