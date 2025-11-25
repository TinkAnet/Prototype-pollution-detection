type Book = {
  title: string;
  author: string;
  isbn: string;
  stockQuantity: number;
};

type Inventory = {
  books: Array<Book>;
};

class BookStore {
  inventory: Inventory;

  constructor() {
    this.inventory = { books: [] };
  }

  addBook(book: Book) {
    const existingBookIndex = this.inventory.books.findIndex(
      (b) => b.isbn === book.isbn
    );
    if (existingBookIndex > -1) {
      this.inventory.books[existingBookIndex].stockQuantity +=
        book.stockQuantity;
    } else {
      this.inventory.books.push(book);
    }
  }
}

type User = {
  name: string;
  age: number;
  sayHello: () => void;
};

let user: User = {
  name: "Anish",
  age: 20,
  sayHello() {
    console.log("Hello");
  },
};

interface Calculator {
  a: number;
  b: number;
  sum: () => number;
  mul: () => number;
}

function createCalculator(a: number, b: number): Calculator {
  return {
    a,
    b,

    sum: function () {
      return this.a + this.b;
    },
    mul: function () {
      return this.a * this.b;
    },
  };
}
let calculator = createCalculator(2, 3);

let ladder = {
  step: 0,
  up() {
    this.step++;
    this.showStep();
    return this;
  },
  down() {
    this.step--;
    this.showStep();
    return this;
  },
  showStep: function () {
    console.log(this.step);
  },
};

interface Accumulator {
  value: number;
  read: () => Accumulator;
}

function createAccumulator(startingValue: number = 0): Accumulator {
  return {
    value: startingValue,
    read: function () {
      console.log(this.value++);
      return this;
    },
  };
}

let accumulator = createAccumulator();

let myString: string = "as sly as a fox, as strong as an ox";
let target: string = "as";
let pos: number = -1;
/* while ((pos = myString.indexOf(target, pos + 1)) !== -1) {
  console.log(pos);
} */

let str: string = "Widget with id";
/* if (str.indexOf("id") !== -1) {
  console.log("We found it!");
} */

str = "stringify";
/* console.log(str.slice(0));
console.log(str.slice(0) === str);

console.log("Z".codePointAt(0));
console.log("z".codePointAt(0));
console.log("ê".codePointAt(0)); */

str = "";
/* for (let i: number = 65; i < 220; i++) {
  str += String.fromCodePoint(i);
} */
// console.log(str);

// console.log("Özerich".localeCompare("Zealand"));

export function ucFirst(str: string): string {
  return str.at(0)?.toUpperCase() + str.slice(1);
}

// console.log(ucFirst("hello"));

export function truncate(str: string, maxlength: number): string {
  if (str.length > maxlength) {
    return str.slice(0, maxlength) + "...";
  }
  return str;
}

// console.log(truncate("What I would like to sell you in this course is", 20));
// console.log(truncate("Hi there how are ya doing?", 2));

function exportCurrencyValue(str: string): number {
  return +str.slice(1);
}

// console.log(exportCurrencyValue("$120"));

let myarr = [1, 2, 3, 4, 5];
myarr.length = 2;
// console.log(myarr);
// myarr.length = 5;
// console.log(myarr);
// console.log(myarr[3]);

let matrix = [[1, 2, 3], undefined, [7, 8, 9]];

// console.log(matrix.at(1)?.at(2));

/* let styles: Array<string> = ["Jazz", "Blues"];
styles.push("Rock-n-Roll");
styles[Math.floor(styles.length / 2)] = "Classics";
console.log(styles.shift());
styles.unshift("Rap", "Reggae");
console.log(styles); */

/* let arr: Array<any> = ["1", "2"];
arr.push(function (this: Array<any>) {
  console.log(this);
});
arr[2](); */

/* let myarr2: Array<string> = ["I", "study", "JavaScript", "right", "now"];
let removed: Array<string> = myarr2.splice(0, 2);
console.log(removed);
let myarr3: Array<string> = ["I", "study", "JavaScript", "right", "now"];
removed = myarr3.splice(1, 3, "eat", "donuts");
console.log(myarr3);
myarr3.forEach((item, index) =>
  console.log(`Item value is "${item}" at index ${index}`)
); */

let users = [
  { id: 1, name: "John" },
  { id: 2, name: "Sarah" },
  { id: 3, name: "Anish" },
];

let targetUser = users.find((user) => user.id === 1);
// console.log(targetUser);

let characters: Array<string> = ["Bilbo", "Gandalf", "Nazgul"];
let lengths: Array<number> = characters.map((character) => character.length);
// console.log(characters, "\n" + lengths);

let arrNum: Array<number> = [1, 2, 3, 4, 5];
// let sum: number = arrNum.reduce((acc, cur) => (acc += cur), 0);
// console.log(sum);

function merge_sort(arr: Array<number>): Array<number> {
  if (arr.length <= 1) {
    return arr;
  }
  let mid: number = Math.floor(arr.length / 2);
  let left: Array<number> = merge_sort(arr.slice(0, mid));
  let right: Array<number> = merge_sort(arr.slice(mid));
  return merge(left, right);
}

function merge(left: Array<number>, right: Array<number>): Array<number> {
  let i: number = 0,
    j: number = 0;
  let sorted: Array<number> = [];
  while (i < left.length && j < right.length) {
    if (left[i] < right[j]) {
      sorted.push(left[i++]);
    } else {
      sorted.push(right[j++]);
    }
  }
  return sorted.concat(left.slice(i)).concat(right.slice(j));
}

let unsorted_arr: Array<number> = [4, 1, 3, 2];
let sorted_arr = merge_sort(unsorted_arr);
// console.log(sorted_arr);

type Salaries = {
  [key: string]: number;
};

function sumSalaries(salariesData: Salaries): number {
  return Object.values(salariesData).reduce((acc, cur) => acc + cur);
}

function countSalaries(salaries: Salaries): number {
  return Object.entries(salaries).reduce((acc) => ++acc, 0);
}

let salaries: Salaries = {
  John: 100,
  Pete: 300,
  Mary: 150,
};

// console.log(topsalaries(salaries));

function topsalaries(salaries: Salaries): string {
  let name: string = "";
  let topsalaries: number = 0;
  for (let [key, value] of Object.entries(salaries)) {
    if (value > topsalaries) {
      name = key;
      topsalaries = value;
    }
  }
  return name;
}

/* console.log(sumSalaries(salaries));
console.log(countSalaries(salaries)); */

type Options = {
  title: string;
  width: number;
  height: number;
};

let options: Options = {
  title: "Menu",
  width: 100,
  height: 200,
};

let { title, width, height } = options;
let { title: t, width: w, height: h } = options;
let { title: ttl, ...rest } = options;

/* console.log(title, width, height);
console.log(t, w, h);
console.log(ttl, rest); */

type Person = {
  name: string;
  years: number;
  isAdmin?: boolean;
};

let person: Person = {
  name: "John",
  years: 30,
};

let { name, years: age, isAdmin = false } = person;

// console.log(Object.entries(salaries));

let now: Date = new Date();
// console.log(now);

let Jan01_1970 = new Date(0);
// console.log(Jan01_1970);

let Jan02_1970 = new Date(24 * 3600 * 1000);
// console.log(Jan02_1970);

let date = new Date();
/* console.log(date.getDate());
console.log(date.getDay());
console.log(date.getFullYear()); */

function diffSubtract(date1: number, date2: number): number {
  return date2 - date1;
}

function diffGetTime(date1: Date, date2: Date): number {
  return date2.getTime() - date1.getTime();
}

function bench(f: Function): number {
  let date1 = new Date(0);
  let date2 = new Date();

  let start = Date.now();
  for (let i = 0; i < 1000000; i++) f(date1, date2);
  return Date.now() - start;
}

/* bench(diffSubtract);
bench(diffGetTime); */

let time1: number = 0;
let time2: number = 0;

let times1: Array<number> = [];
let times2: Array<number> = [];

/* for (let i = 0; i < 10; i++) {
  let t1: number = bench(diffSubtract);
  let t2: number = bench(diffGetTime);
  (time1 += t1), (time2 += t2);
  times1.push(t1), times2.push(t2);
} */

/* console.log(times1);
console.log(times2);
console.log(times1.reduce((sum, cur) => sum + cur) / times1.length);
console.log(times2.reduce((sum, cur) => sum + cur) / times2.length); */

let Feb20_2012 = Date.parse("2012-02-20T03:03:12");
// console.log(Feb20_2012);

function getWeekDay(date: Date): string {
  let days: Array<string> = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"];
  return days[date.getDay()];
}

let date3 = new Date(2012, 0, 3);
// console.log(getWeekDay(date3));

let student = {
  name: "Anish",
  age: 23,
  isAdmin: false,
  courses: ["html", "css", "python"],
  spouse: null,
};

let json: string = JSON.stringify(student);
// console.log(json);

interface LooseObject {
  [key: string]: any;
}

let room: LooseObject = {
  number: 23,
};

let meetup: LooseObject = {
  title: "conference",
  participants: ["john", "ann"],
};

meetup.place = room;
room.occupiedBy = meetup;

let numbers: string = "[0, 1, 2, 3, 4]";
numbers = JSON.parse(numbers);
// console.log(numbers);

let string2: string =
  '{"title":"Conference","date":"2017-11-30T12:00:00.000Z"}';

let meetup2 = JSON.parse(string2, function (key, value) {
  if (key == "date") return new Date(value);
  return value;
});

// console.log(meetup2.date.getDate());

function sumAll(...args: Array<number>): number {
  let sum = 0;
  for (let arg of args) sum += arg;
  return sum;
}

// console.log(sumAll(1, 2, 3, 4, 5, 6));

let numbers2: Array<number> = [1, 2, 3, 4, 5];
// console.log(Math.max(...numbers2));
// console.log(...numbers2);

let numbers3: Array<number> = [3, 2, 4, 4, 5, 12];
numbers2 = [...numbers2, ...numbers3];
// console.log(numbers2);
// console.log(numbers2.length);

let word: string = "hello";

/* let start1: number = Date.now();
for (let i = 0; i < 1_000_000_00; i++) {
  let strArr: Array<string> = [...word];
}
let end1: number = Date.now();

let start2: number = Date.now();
for (let i = 0; i < 1_000_000_00; i++) {
  let strArr: Array<string> = Array.from(word);
}
let end2: number = Date.now(); */

// console.log(`${end1 - start1}ms`);
// console.log(`${end2 - start2}ms`); // this one is faster

let arr = [1, 2, 3];
let arrCopy = [...arr];
/* console.log(arr === arrCopy);
console.log(arr == arrCopy);
console.log(JSON.stringify(arr) === JSON.stringify(arrCopy));
console.log(JSON.stringify(arr) == JSON.stringify(arrCopy)); */

let obj: LooseObject = { a: 1, b: 2, c: 3 };
let objCopy = { ...obj };
obj.d = 4;

// console.log(JSON.stringify(obj));
// console.log(JSON.stringify(objCopy));

////////////////////////////////
/* variable scope and closure */
////////////////////////////////

function makeCounter(): Function {
  let count: number = 0;
  return () => count++;
}

let counter: Function = makeCounter();
// console.log(counter());
// console.log(counter());

function makeWorkerGlobal(): Function {
  return () => console.log(workerName);
}

let workerName: string = "John";

let worker: Function = makeWorkerGlobal();
// worker();

function makeWorkerLocal(): Function {
  let workerName2: string = "Alex";
  return () => console.log(workerName2);
}

let workerName2: string = "Alexa";
let worker2: Function = makeWorkerLocal();
// worker2();

function sum(a: number): Function {
  return (b: number): number => a + b;
}

// console.log(sum(1)(2));
// console.log(sum(5)(-1));

function inBetween(low: number, high: number): Function {
  return (value: number) => value >= low && value <= high;
}

arr = [1, 2, 3, 4, 5, 6, 7, 8, 9];
// console.log(arr.filter((value) => inBetween(3, 6)(value)));

/* let myFunction: () => void = function (): void {
  console.log("Hi");
};

let timerId = setTimeout(myFunction, 1000); */

/* let timerId = setInterval(() => console.log("hi"), 1000);
setTimeout(() => {
  clearInterval(timerId);
  console.log("stop");
}, 5001); */

type Func<T> = (x: T) => T;

function cachingDecorator<T>(func: Func<T>): Func<T> {
  let cache = new Map<T, T>();

  return function (x: T): T {
    if (cache.has(x)) {
      return cache.get(x)!;
    }
    let result = func(x);
    cache.set(x, result);
    return result;
  };
}

let slow: Func<number> = function (x: number): number {
  console.log(`Function called with ${x}`);
  return x;
};

slow = cachingDecorator(slow);
// console.log(slow(1));
// console.log(slow(1));
// console.log(slow(1));
// console.log(slow(2));

Object.defineProperty(user, "name", {
  value: "John",
  writable: false,
});
let descriptor = Object.getOwnPropertyDescriptor(user, "name");
// console.log(JSON.stringify(descriptor, null, 2));

let userGetterSetter = {
  name: "John",
  surname: "Smith",

  get fullName() {
    return `${this.name} ${this.surname}`;
  },

  set fullName(fullName: string) {
    [this.name, this.surname] = fullName.split(" ");
  },
};

/* console.log(userGetterSetter.fullName);
userGetterSetter.fullName = "Anish Sharma";
console.log(userGetterSetter.name);
console.log(userGetterSetter.surname);
console.log(userGetterSetter.fullName); */

/* let animal = {
  eats: true,
};

let rabbit = Object.create(animal); */
// console.log(rabbit.eats);
// console.log(Object.getPrototypeOf(rabbit));
// Object.setPrototypeOf(rabbit, {});

/* class Animal {
  name: string = "animal";
  noise: string = "...";

  constructor(name: string = "animal", noise: string = "...") {
    this.name = name;
    this.noise = noise;
  }

  makeNoise(): void {
    console.log(this.noise);
  }
}

let dog: Animal = new Animal("Bolt", "Woof!");
let fox: Animal = new Animal("Fox"); */
// dog.makeNoise();
// fox.makeNoise();
// console.log(typeof Animal);
// console.log(typeof dog);
// console.log(Animal.prototype.makeNoise);

class Clock {
  timer: NodeJS.Timeout | undefined;
  template: string;

  constructor(template: string = "h:m:s") {
    this.template = template;
  }

  render(): string {
    let date: Date = new Date();

    let hours: number | string = date.getHours();
    if (hours < 10) hours = "0" + hours;

    let mins: number | string = date.getMinutes();
    if (mins < 10) mins = "0" + mins;

    let secs: number | string = date.getSeconds();
    if (secs < 10) secs = "0" + secs;

    let output: string = this.template
      .replace("h", () => hours.toString())
      .replace("m", () => mins.toString())
      .replace("s", () => secs.toString());

    console.log(output);
    return output;
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }

  start() {
    this.render();
    this.timer = setInterval(this.render.bind(this), 1000);
  }
}

/* let clock: Clock = new Clock("h:m:s");
clock.start();
setTimeout(() => clock.stop(), 5000); */

class Animal {
  name: string;
  speed: number;

  constructor(name: string) {
    this.name = name;
    this.speed = 0;
  }

  run(speed: number) {
    this.speed = speed;
    console.log(`${this.name} runs with speed ${this.speed}`);
  }

  stop() {
    this.speed = 0;
    console.log(`${this.name} stands still`);
  }
}

class Rabbit extends Animal {
  earLength: number;

  constructor(name: string, earLength: number) {
    super(name);
    this.earLength = earLength;
  }

  hide() {
    console.log(`${this.name} hides`);
  }

  stop() {
    super.stop();
    this.hide();
  }
}

let rabbit = new Rabbit("White Rabbit", 5);
/* rabbit.run(5);
console.log(rabbit.speed);
rabbit.hide(); */

class CoffeeMachine {
  #waterLimit: number = 100;
  private _waterAmount: number = 0;
  private _power: number;

  constructor(power: number) {
    this._power = power;
    console.log(`Created a coffee machine with ${power}W power.`);
  }

  #fixWaterAmount(value: number) {
    if (value < 0) return 0;
    if (value > this.#waterLimit) return this.#waterLimit;
    return value;
  }

  setWaterAmount(value: number) {
    this.#waterLimit = this.#fixWaterAmount(value);
  }

  get waterAmount() {
    return this._waterAmount;
  }

  get power() {
    return this._power;
  }
}

// let coffeeMachine = new CoffeeMachine(100);
// coffeeMachine.setWaterAmount(50);
// console.log(coffeeMachine.waterAmount);

let sayMixIn = {
  sayHi() {
    console.log("HI");
  },
  sayBye() {
    console.log("BYE");
  },
};

class Individual {
  name: string;
  constructor(name: string) {
    this.name = name;
  }
}

Object.assign(Individual.prototype, sayMixIn);

let error = new Error("Things happen o_O");
// console.log(error.name);
// console.log(error.message);

let json2 = '{"name": "anish", age" 20}';

/* try {
  let user = JSON.parse(json2);
  if (!user.surname) {
    throw new SyntaxError("Surname field does not exist on user");
  }
  console.log(user);
} catch (err) {
  if (err instanceof SyntaxError) {
    console.log(`JSON error: ${err}`);
  } else {
    console.log(err);
  }
} */

/* let promise = new Promise((resolve, reject) => {
  setTimeout(() => resolve("done"), 1000);
  // setTimeout(() => reject(new Error("Whoops")), 1000);
})
  .then((result) => console.log(result))
  .catch((error) => console.log(error)); */

/* function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

delay(3000).then(() => console.log("runs after 3 seconds")); */

let promise = new Promise<number>(function (resolve) {
  setTimeout(() => resolve(1), 1000);
})
  .then((result) => {
    console.log(result * 2);
    return ++result;
  })
  .then((result) => {
    setTimeout(() => console.log(result * 2), 1000);
  });

/* promise.then(function (result) {
  console.log(result); // 1
});

promise.then(function (result) {
  console.log(result); // 1
});

promise.then(function (result) {
  console.log(result); // 1
}); */

fetch("/example/url")
  .then((response) => response.json())
  .then((user) => alert(user.name));
