/* ASSIGNMENT */
x = 1;
var a = 5;
var b = 10;
var c = function (a, b, c) {
  console.log(' 1 : ' + x);
  console.log(' 2 : ' + a);
  var f = function (a, b, c) {
    b = a;
    console.log(' 3 : ' + b);
    b = c;
    var x = 5;
  };
  f(a, b, c);
  console.log(' 4 : ' + b); //9
  var x = 10;
};

c(8, 9, 10);
console.log(' 5 : ' + b); //10
console.log(' 6 : ' + x); //1

/* OUTPUT:
undefined
8
8
9
10
1

--------

Global Scope : 
Global scope is the scope that contains all of the things defined outside of all code blocks. A global variable has a global scope and whenever an undeclared variable is assigned
with a value, the variable is also a part of global scope. Any variables assigned without an explicit scope (using the var, let, or const keywords) automatically become global variables. The same is true for functions.

Local Scope: It contains things defined inside a code blocks.
* Local variables cannot be accessed or modified outside the function declaration.






JavaScript has global scope and local scope.
Variables declared and initialized outside any function become global variables.
Variables declared and initialized inside function becomes local variables to that function.
Variables declared without var keyword inside any function becomes global variables automatically.
Global variables can be accessed and modified anywhere in the program.
Local variables cannot be accessed outside the function declaration.
Global variable and local variable can have same name without affecting each other.
JavaScript does not allow block level scope inside { } brackets.
*/
/* Question 3 */
var globalvar = 1;
function outerFunction() {
  var outerVar = 2;
  function innerFunction() {
    var innerVar = 3;
  }
  innerFunction();
}
/*
a. 

*/

/* Question 4*/
var x = 9;
function myFunction() {
  return x * x;
}

console.log(myFunction()); //81
x = 5;
console.log(myFunction()); //25

/* Question 5 */
var foo = 1;
function bar() {
  if (!foo) {
    var foo = 10;
  }
  console.log(foo); //10
}
bar();

// let tenMinuteInterval = setInterval(function () {
//   alert('1 minute have passed');
// }, 1000 * 60);

/*=============*/
// let user = {
//   firstName: 'Ilya',
//   sayHi() {
//     let arrow = () => alert(this.firstName);
//     arrow();
//   },
// };

// user.sayHi(); // Ilya

/*==============*/
console.log('======');
/*==============*/

var x = 5;
function test() {
  for (let x = 0; x < 9; x++) {
    //block scope, so let won't go to top of function scope, only remains within block scope

    console.log(x); // 1,2,3,4,5,6,7,8
  }
  console.log(x); // 5 !!! not 9, b/c let x won't lie in this scope
}
test();

// // shortest("hello", "z", "bye")

// function shortest(...args) {
//   console.log('-astar');

//   console.log(
//     args.reduce(
//       prevValue,
//       currValue => {
//         prevValue.length < currValue.length ? currValue : prevValue;
//       },
//       args[0]
//     )
//   );
//   let shortest = args[0];
//   console.log('--');
//   console.log(shortest.length);
//   for (arg of args) {
//     console.log(arg.length);
//   }
//   return shortest;
// }

// let adsf = shortest('aasaasd', 'asdfa');
// console.log(adsf);

function shortest(...wordList) {
  return wordList.reduce((prev, current) =>
    prev.length < current.length ? prev : current
  );
}

let as = shortest('hello', 'z', 'bye');
console.log('shortest is: ' + as);

function longestNoSpace(...strings) {
  return strings
    .filter(str => !str.includes(' '))
    .map(str => str.length)
    .reduce((prevMax, curr) => (curr > prevMax ? curr : prevMax), 0);
}

let da = longestNoSpace('hello', 'world!');
console.log(da);

//////////////////
console.log('--------------- Inheritance -------------------');

let Animal = {
  name: 'Mammal',
  age: 1,
  tail: true,
};

let Animal1 = {
  name: 'Mammal1',
  age: 1,
  tail: true,
};

let Cat = {
  whiskers: true,
  __proto__: Animal, // makes -> Cat is an animal
  sayName: function () {
    console.log(this.name);
  },
};

console.log(Animal);
console.log(Animal.hasOwnProperty());
console.log(Cat);
console.log(Cat.__proto__); // gives {name : Mammal, age: 1, tail: true}
Cat.__proto__.age = 2;
console.log('after changes : Cat.__proto__.age = 2 ');
console.log(Cat.__proto__); // gives {name : Mammal, age: 2, tail: true}

Cat.__proto__ = Animal1;
console.log(Cat);
console.log(Cat.name); // gives name: 'Mammal' from Animal class since Cat doesn't have 'name' property
Cat.name = 'Cat name'; // assigning Cat class with name property
console.log(Cat);
// {
//     "whiskers": true,
//     "name": "Cat name"
// }
console.log(Cat.__proto__.name); // Mammal1 refers to Animal property 'name'

console.log(Cat.sayName()); // Cat name

Cat.__proto__.sayName = function () {
  console.log('here', this.name);
};
console.log('--------');
Cat.sayName(); //Cat name
console.log(Cat.__proto__); //z {name: 'Mammal1', age: 1.....}
console.log(Animal1); // i.e Cat.__proto__ refers to Animal1
console.log(Cat.__proto__.sayName()); //Mammal1

let Dog = {
  sound: 'Bark',
  name: 'Appollo',
  __proto__: Animal1, //Dog is an animal
  addProperty: function () {
    this.__proto__.numberOfLegs = 4; //adds attribute to Animal1
  },
};
///* DOG *///
console.log(Dog);
Dog.sayName();
Dog.addProperty(); // changing attribute value in runtime
console.log(Animal1);

let Mammal = {
  hasFur: true,
  walk: function () {
    console.log(this.name + '.....walking.....');
  },
};

console.log(Dog.hasFur); //undefined
Dog.__proto__ = Mammal;
console.log(Dog);
console.log(Dog.hasFur); //true
// now back to Animal
Dog.__proto__ = Animal1;
console.log(Dog);
Dog.sayName();
console.log(Dog.hasFur); // perviously existing attributes not exist after assigning to 'Animal'

// now let's say I want to have walk() from Mammal but the parent still is Animal
// i.e Borrowing property from other class
Dog.__proto__.walk = Mammal.walk;
console.log(Dog);
Dog.walk();
// even cat will have this
Cat.walk();

Mammal.walk(); // undefined....walking....

/* IN JAVA:
public Fox(int age, String name, String color){
    this.age = age;
    this.name = name;
    this.color = color;
}
*/
/* IN JS */
function Fox(age, name, color) {
  this.age = age;
  this.name = name;
  this.color = color;
  //   this.__proto__ = Animal; // directly prototype set to Animal.
}

//!!!NOTE: not __proto__
Fox.prototype.myName = function () {
  return this.name;
};

let f = new Fox(5, 'Mc Fox', 'Red');
console.log(f); // an object is created but the parent object prototype is nested under another prototype. This is the difference when we create using constructor
// b/c constructor is another object.
console.log(f.myName());
console.log(f.__proto__.__proto__);
console.log(Fox.prototype.__proto__);
// console.log(Fox.prototype);

function Duck(x, y) {
  this.x = x;
  this.y = y;
}

Duck.prototype = Fox.prototype; //adding prototype
let d = new Duck('D', 'U');
console.log(d);

function Shape(x, y) {
  this.x = x;
  this.y = y;
}

Shape.prototype.distanceFromOrigins = function () {
  return this.x - this.y;
};

console.log(Shape.prototype);

function Square(x, y, width, height) {
  this.x = x;
  this.y = y;
  this.width = width;
  this.height = height;
}

Square.prototype.__proto__ = Shape.prototype;
let squarex = new Square(3, 5, 3, 2);
console.log(squarex);

function Person(name) {
  this.name;
}
Person.prototype.speak = function () {
  return this.name;
};

function Dave(name) {
  this.name = name;
}

Dave.prototype.__proto__ = Person.prototype;

let dave = new Dave('Dave Smith');

console.log('dave', dave.speak());
console.log(dave);

function Charlie(name) {
  this.name = name;
}

Charlie.prototype.__proto__ = Person.prototype;
Charlie.prototype.eat = function () {
  return 'eating....';
};
let charlie = new Charlie('Charlez Brown');
console.log(charlie.speak());
console.log(charlie.eat());
console.log(charlie);

// function Dave(name) {
//   this.name = name;
// }
// Dave.prototype.__proto__ = Person.prototype;

// let dave = new Dave();

// // Dave.prototype.name = dave.name;

// function Charlie(name) {
//   this.name = name;
// }
// Charlie.prototype.__proto__ = Person.prototype;

// let charlie = new Charlie('Charlez Brown');
// // Charlie.prototype.name = charlie.name;
// Charlie.prototype.eat = function () {
//   return 'eating....';
// };

// console.log(dave);

let testArray = ['David', 'mania', 'kushal', 'Sheva'];

let test1 = testArray.filter(str => str[0] == str[0].toUpperCase());
console.log(test1);

let reduce = testArray.reduce((acc, cv) => (acc += cv), '');
console.log(reduce);

function sumNumbers(...args) {
  //   let sum = 0;
  //   for (arg of args) {
  //     sum += arg;
  //   }
  //   return sum;
  return args.reduce((acc, cv) => acc + cv, 0);
}

let sumA = sumNumbers(2, 3, 4, 5, 6);
console.log(sumA);

function spread1(x, y) {
  return [...x, ...y];
}

let sp = spread1([1, 2, 3, 4], [5, 6, 7, 8]);
console.log(sp);

/*Implement the addNumber method to return a function
which is a closure to its input (x) which adds that input
to its own input (y) and returns the value of their sum*/

function addNumber(x) {
  return function (y) {
    return x + y;
  };
}

let usingModule = (function () {
  var x = 5;
  var y = 8;
  function returnx() {
    return x;
  }
  function returny() {
    return y;
  }
  function doMath() {
    return returny() + returnx();
  }
  return {
    math: doMath,
  };
})();
console.log('Math: ' + usingModule.math());
