/************************************************
 * THERE ARE EXIST IN TYPESCRIPT NOT JAVASCRIPT *
 ************************************************/

/* -------------------------------------------------------------------------- */
/*                             array type generic                             */
/* -------------------------------------------------------------------------- */

const names: Array<string> = []; // same as : string[]
const names1: Array<string | number> = [];
const names2: Array<any> = [];

/* -------------------------------------------------------------------------- */
/*                            promise type generic                            */
/* -------------------------------------------------------------------------- */

const promise: Promise<string> = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve("this is done!");
  }, 2000);
});

promise.then(data => {
  data.split(" ");
});

/* -------------------------------------------------------------------------- */
/*                         build our own generic type                         */
/* -------------------------------------------------------------------------- */
//wrong
function merge(objA: object, objB: object) {
  return Object.assign(objA, objB);
}

const mergedObj = merge({ name: "Max" }, { age: 30 }); // we can use type casting but it is not common eg: as {name:string,age:number}

mergedObj.name; // type script doesn't know this

//correct
function merge2<T, U>(objA: T, objB: U) {
  return Object.assign(objA, objB);
}

const mergedObj2 = merge2({ name: "Max" }, { age: 30 });

mergedObj2.name;

/****************************************************************************
 * YOU CAN ALSO SPECIFY TYPE OF ARGUMENTS WHEN YOU WANNA CALL THAT FUNCTION *
 ****************************************************************************/
const mergedObj3 = merge2<object, object>({ name: "Max" }, { age: 30 });
const mergedObj4 = merge2<{ name: string; hobbies: string }, { age: number }>(
  { name: "Max", hobbies: "play" },
  { age: 30 }
);

/* -------------------------------------------------------------------------- */
/*                              type constraints                              */
/* -------------------------------------------------------------------------- */
const mergedObj5 = merge2({ name: "Max" }, 30); //  we don't wanna argument 30 we should use constraints

function merge3<T extends object, U extends object>(objA: T, objB: U) {
  return Object.assign(objA, objB);
}

const mergedObj6 = merge3({ name: "Max" }, 30); //  there you go you cannot assign 30 as argument

interface Lengthy {
  length: number;
}
function countAndPrint<T extends Lengthy>(element: T): [T, string] {
  let descriptionText = "Got no value.";
  if (element.length === 1) {
    descriptionText = "Got element.";
  } else if (element.length > 1) {
    descriptionText = "Got " + element.length + " elements.";
  }
  return [element, descriptionText];
}

console.log(countAndPrint("hi there"));
console.log(countAndPrint(["Sports", "Cooking"]));
console.log(countAndPrint([10]));

/* -------------------------------------------------------------------------- */
/*                             key of constraints                             */
/* -------------------------------------------------------------------------- */

function extractAndConvert<T extends object, U extends keyof T>(
  obj: T,
  key: U
) {
  return "Value: " + obj[key];
}

extractAndConvert({ name: "Max" }, "age"); //wrong
extractAndConvert({ name: "Max" }, "name"); //correct

/* -------------------------------------------------------------------------- */
/*                                generic class                               */
/* -------------------------------------------------------------------------- */

class DataStorage<T extends string | number | boolean> {
  private data: T[] = [];
  addItem(item: T) {
    this.data.push(item);
  }
  removeItem(item: T) {
    this.data.splice(this.data.indexOf(item), 1);
  }
  getItems() {
    return [...this.data];
  }
}

const testStorage = new DataStorage<string>();
testStorage.addItem("Max");
testStorage.addItem("Manu");
testStorage.removeItem("Max");
console.log(testStorage.getItems());

const numberStorage = new DataStorage<number>();
numberStorage.addItem(5);
numberStorage.addItem(6);
numberStorage.removeItem(5);
console.log(numberStorage.getItems());

/* -------------------------------------------------------------------------- */
/*                            generic Utility Types                           */
/* -------------------------------------------------------------------------- */

interface CourseGoal {
  title: string;
  description: string;
  completeUntil: Date;
}

function createCourseGoal(
  title: string,
  description: string,
  date: Date
): CourseGoal {
  let courseGoal: Partial<CourseGoal> = {};

  courseGoal.title = title;
  courseGoal.description = description;
  courseGoal.completeUntil = date;
  return courseGoal as CourseGoal;
}

const names3: Readonly<string[]> = ["Max", "Anna"];
names3.push("Manu"); //you cannot do this
names3.pop(); //you cannot do this


