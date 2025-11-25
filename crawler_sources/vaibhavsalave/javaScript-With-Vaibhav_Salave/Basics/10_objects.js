// JavaScript Objects - Complete Guide

// =====================================================
// OBJECT CREATION
// =====================================================

console.log("=== OBJECT CREATION ===");

// Object literal
let person = {
    name: "John",
    age: 30,
    city: "New York"
};
console.log("Person object:", person);

// Empty object
let emptyObj = {};
console.log("Empty object:", emptyObj);

// Object constructor
let student = new Object();
student.name = "Alice";
student.grade = "A";
console.log("Student object:", student);

// Object with methods
let calculator = {
    add: function(a, b) {
        return a + b;
    },
    subtract: function(a, b) {
        return a - b;
    },
    // ES6 method shorthand
    multiply(a, b) {
        return a * b;
    }
};

console.log("Calculator add:", calculator.add(5, 3));
console.log("Calculator multiply:", calculator.multiply(4, 6));

// Object with computed property names
let propName = "dynamicProp";
let obj = {
    [propName]: "Dynamic value",
    ["computed" + "Prop"]: "Another dynamic value"
};
console.log("Object with computed props:", obj);

// =====================================================
// PROPERTY ACCESS
// =====================================================

console.log("\n=== PROPERTY ACCESS ===");

let car = {
    brand: "Toyota",
    model: "Camry",
    year: 2022,
    "engine-type": "V6" // Property with special characters
};

// Dot notation
console.log("Brand:", car.brand);
console.log("Year:", car.year);

// Bracket notation
console.log("Model:", car["model"]);
console.log("Engine type:", car["engine-type"]); // Required for special characters

// Dynamic property access
let propToAccess = "brand";
console.log("Dynamic access:", car[propToAccess]);

// Accessing non-existent property
console.log("Non-existent property:", car.color); // undefined

// =====================================================
// ADDING AND MODIFYING PROPERTIES
// =====================================================

console.log("\n=== ADDING AND MODIFYING PROPERTIES ===");

let book = {
    title: "JavaScript Guide",
    author: "John Doe"
};

console.log("Original book:", book);

// Add new property
book.pages = 300;
book["publisher"] = "Tech Books";

console.log("After adding properties:", book);

// Modify existing property
book.title = "Complete JavaScript Guide";
book["author"] = "Jane Smith";

console.log("After modifying:", book);

// Delete property
delete book.publisher;
console.log("After deleting publisher:", book);

// =====================================================
// OBJECT METHODS
// =====================================================

console.log("\n=== OBJECT METHODS ===");

let user = {
    firstName: "Alice",
    lastName: "Johnson",
    age: 28,
    
    // Method using 'this'
    getFullName: function() {
        return this.firstName + " " + this.lastName;
    },
    
    // ES6 method shorthand
    greet() {
        return `Hello, I'm ${this.getFullName()}`;
    },
    
    // Arrow function (doesn't have its own 'this')
    getInfo: () => {
        // 'this' here refers to global object, not the user object
        return "Info method";
    },
    
    // Method that modifies object
    celebrateBirthday() {
        this.age++;
        console.log(`Happy birthday! Now ${this.age} years old.`);
    }
};

console.log("Full name:", user.getFullName());
console.log("Greeting:", user.greet());
console.log("Info:", user.getInfo());

user.celebrateBirthday();
console.log("Updated age:", user.age);

// =====================================================
// OBJECT DESTRUCTURING (ES6)
// =====================================================

console.log("\n=== OBJECT DESTRUCTURING ===");

let employee = {
    name: "Bob Wilson",
    position: "Developer",
    salary: 75000,
    benefits: {
        health: true,
        dental: true,
        vacation: 21
    }
};

// Basic destructuring
let {name, position} = employee;
console.log(`Employee: ${name}, Position: ${position}`);

// Destructuring with different variable names
let {name: empName, salary: empSalary} = employee;
console.log(`${empName} earns $${empSalary}`);

// Destructuring with default values
let {name: nm, bonus = 5000} = employee;
console.log(`${nm} has bonus: $${bonus}`);

// Nested destructuring
let {benefits: {health, vacation}} = employee;
console.log(`Health: ${health}, Vacation days: ${vacation}`);

// Rest operator in destructuring
let {name: employeeName, ...otherDetails} = employee;
console.log("Employee name:", employeeName);
console.log("Other details:", otherDetails);

// =====================================================
// OBJECT.KEYS, VALUES, ENTRIES
// =====================================================

console.log("\n=== OBJECT.KEYS, VALUES, ENTRIES ===");

let product = {
    id: 1,
    name: "Laptop",
    price: 999,
    category: "Electronics"
};

// Object.keys() - get property names
let keys = Object.keys(product);
console.log("Object keys:", keys);

// Object.values() - get property values
let values = Object.values(product);
console.log("Object values:", values);

// Object.entries() - get key-value pairs
let entries = Object.entries(product);
console.log("Object entries:", entries);

// Iterate through object
console.log("Iterating through object:");
for (let [key, value] of Object.entries(product)) {
    console.log(`${key}: ${value}`);
}

// =====================================================
// OBJECT CLONING AND MERGING
// =====================================================

console.log("\n=== OBJECT CLONING AND MERGING ===");

let original = {
    name: "Original",
    details: {
        type: "test",
        count: 5
    }
};

// Shallow copy using spread operator
let shallowCopy = {...original};
console.log("Shallow copy:", shallowCopy);

// Shallow copy using Object.assign()
let assignCopy = Object.assign({}, original);
console.log("Assign copy:", assignCopy);

// Deep copy using JSON (limitation: doesn't work with functions, undefined, symbols)
let deepCopy = JSON.parse(JSON.stringify(original));
console.log("Deep copy:", deepCopy);

// Merging objects
let obj1 = {a: 1, b: 2};
let obj2 = {b: 3, c: 4};
let obj3 = {c: 5, d: 6};

let merged = {...obj1, ...obj2, ...obj3};
console.log("Merged objects:", merged);

// Object.assign for merging
let mergedAssign = Object.assign({}, obj1, obj2, obj3);
console.log("Merged with assign:", mergedAssign);

// =====================================================
// OBJECT PROPERTY DESCRIPTORS
// =====================================================

console.log("\n=== PROPERTY DESCRIPTORS ===");

let testObj = {};

// Define property with descriptor
Object.defineProperty(testObj, 'readOnlyProp', {
    value: 'Cannot change this',
    writable: false,
    enumerable: true,
    configurable: false
});

console.log("Read-only property:", testObj.readOnlyProp);

// Try to modify (will fail silently or throw error in strict mode)
testObj.readOnlyProp = "New value";
console.log("After attempting to modify:", testObj.readOnlyProp);

// Get property descriptor
let descriptor = Object.getOwnPropertyDescriptor(testObj, 'readOnlyProp');
console.log("Property descriptor:", descriptor);

// Define multiple properties
Object.defineProperties(testObj, {
    prop1: {
        value: 'Property 1',
        writable: true
    },
    prop2: {
        value: 'Property 2',
        enumerable: false // Won't show in for...in or Object.keys
    }
});

console.log("All enumerable keys:", Object.keys(testObj));
console.log("All property names:", Object.getOwnPropertyNames(testObj));

// =====================================================
// GETTERS AND SETTERS
// =====================================================

console.log("\n=== GETTERS AND SETTERS ===");

let circle = {
    _radius: 0, // Convention: underscore indicates private property
    
    get radius() {
        return this._radius;
    },
    
    set radius(value) {
        if (value < 0) {
            console.log("Radius cannot be negative");
            return;
        }
        this._radius = value;
    },
    
    get area() {
        return Math.PI * this._radius * this._radius;
    },
    
    get circumference() {
        return 2 * Math.PI * this._radius;
    }
};

circle.radius = 5;
console.log("Radius:", circle.radius);
console.log("Area:", circle.area.toFixed(2));
console.log("Circumference:", circle.circumference.toFixed(2));

// Try to set negative radius
circle.radius = -3; // Should show error message

// Using Object.defineProperty for getters/setters
let temperature = {
    _celsius: 0
};

Object.defineProperty(temperature, 'celsius', {
    get() {
        return this._celsius;
    },
    set(value) {
        this._celsius = value;
    }
});

Object.defineProperty(temperature, 'fahrenheit', {
    get() {
        return (this._celsius * 9/5) + 32;
    },
    set(value) {
        this._celsius = (value - 32) * 5/9;
    }
});

temperature.celsius = 25;
console.log(`${temperature.celsius}°C = ${temperature.fahrenheit}°F`);

temperature.fahrenheit = 86;
console.log(`${temperature.fahrenheit}°F = ${temperature.celsius}°C`);

// =====================================================
// OBJECT PROTOTYPES
// =====================================================

console.log("\n=== OBJECT PROTOTYPES ===");

// Constructor function
function Animal(name, species) {
    this.name = name;
    this.species = species;
}

// Add method to prototype
Animal.prototype.makeSound = function() {
    return `${this.name} makes a sound`;
};

Animal.prototype.getInfo = function() {
    return `${this.name} is a ${this.species}`;
};

// Create instances
let dog = new Animal("Buddy", "Dog");
let cat = new Animal("Whiskers", "Cat");

console.log(dog.makeSound());
console.log(cat.getInfo());

// Check prototype
console.log("Dog prototype:", Object.getPrototypeOf(dog) === Animal.prototype);

// Add property to specific instance
dog.age = 3;
console.log("Dog age:", dog.age);
console.log("Cat age:", cat.age); // undefined

// =====================================================
// OBJECT.CREATE()
// =====================================================

console.log("\n=== OBJECT.CREATE() ===");

// Create object with specific prototype
let vehiclePrototype = {
    start: function() {
        return `${this.brand} ${this.model} is starting`;
    },
    stop: function() {
        return `${this.brand} ${this.model} has stopped`;
    }
};

let car1 = Object.create(vehiclePrototype);
car1.brand = "Honda";
car1.model = "Civic";

console.log(car1.start());

// Create with properties
let car2 = Object.create(vehiclePrototype, {
    brand: {
        value: "Toyota",
        writable: true,
        enumerable: true
    },
    model: {
        value: "Prius",
        writable: true,
        enumerable: true
    }
});

console.log(car2.stop());

// Create object with null prototype (no inherited properties)
let pureObject = Object.create(null);
pureObject.customProp = "No prototype";
console.log("Pure object:", pureObject);
console.log("Has toString?", pureObject.toString); // undefined

// =====================================================
// OBJECT INHERITANCE
// =====================================================

console.log("\n=== OBJECT INHERITANCE ===");

// Parent constructor
function Vehicle(brand, year) {
    this.brand = brand;
    this.year = year;
}

Vehicle.prototype.getAge = function() {
    return new Date().getFullYear() - this.year;
};

// Child constructor
function Car(brand, year, doors) {
    Vehicle.call(this, brand, year); // Call parent constructor
    this.doors = doors;
}

// Set up inheritance
Car.prototype = Object.create(Vehicle.prototype);
Car.prototype.constructor = Car;

// Add child-specific method
Car.prototype.getDetails = function() {
    return `${this.brand} (${this.year}) with ${this.doors} doors`;
};

let myCar = new Car("BMW", 2018, 4);
console.log("Car details:", myCar.getDetails());
console.log("Car age:", myCar.getAge()); // Inherited method

// =====================================================
// OBJECT UTILITIES
// =====================================================

console.log("\n=== OBJECT UTILITIES ===");

let sampleObj = {a: 1, b: 2, c: 3};

// Object.freeze() - make object immutable
let frozenObj = Object.freeze({...sampleObj});
frozenObj.a = 999; // Won't change
console.log("Frozen object:", frozenObj);

// Object.seal() - prevent adding/removing properties
let sealedObj = Object.seal({...sampleObj});
sealedObj.a = 999; // Can modify existing properties
sealedObj.d = 4;   // Can't add new properties
console.log("Sealed object:", sealedObj);

// Check object state
console.log("Is frozen?", Object.isFrozen(frozenObj));
console.log("Is sealed?", Object.isSealed(sealedObj));
console.log("Is extensible?", Object.isExtensible(sampleObj));

// Object.preventExtensions() - prevent adding new properties
let nonExtensible = Object.preventExtensions({...sampleObj});
nonExtensible.a = 999; // Can modify
nonExtensible.d = 4;   // Can't add
console.log("Non-extensible:", nonExtensible);

// =====================================================
// PRACTICAL EXAMPLES
// =====================================================

console.log("\n=== PRACTICAL EXAMPLES ===");

// Example 1: Object factory function
function createUser(name, email, role = 'user') {
    return {
        name,
        email,
        role,
        permissions: role === 'admin' ? ['read', 'write', 'delete'] : ['read'],
        
        hasPermission(permission) {
            return this.permissions.includes(permission);
        },
        
        addPermission(permission) {
            if (!this.permissions.includes(permission)) {
                this.permissions.push(permission);
            }
        },
        
        getProfile() {
            return {
                name: this.name,
                email: this.email,
                role: this.role
            };
        }
    };
}

let admin = createUser("Admin User", "admin@example.com", "admin");
let regularUser = createUser("John Doe", "john@example.com");

console.log("Admin permissions:", admin.permissions);
console.log("Can admin delete?", admin.hasPermission('delete'));
console.log("Can user write?", regularUser.hasPermission('write'));

// Example 2: Object validation
function validateObject(obj, schema) {
    let errors = [];
    
    for (let field in schema) {
        let rules = schema[field];
        let value = obj[field];
        
        if (rules.required && (value === undefined || value === null)) {
            errors.push(`${field} is required`);
            continue;
        }
        
        if (value !== undefined && rules.type && typeof value !== rules.type) {
            errors.push(`${field} must be of type ${rules.type}`);
        }
        
        if (rules.minLength && value.length < rules.minLength) {
            errors.push(`${field} must be at least ${rules.minLength} characters`);
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
}

let userSchema = {
    name: {required: true, type: 'string', minLength: 2},
    email: {required: true, type: 'string'},
    age: {type: 'number'}
};

let userData1 = {name: "John", email: "john@email.com", age: 25};
let userData2 = {name: "A", age: "not a number"};

console.log("Validation 1:", validateObject(userData1, userSchema));
console.log("Validation 2:", validateObject(userData2, userSchema));

// Example 3: Object deep merge
function deepMerge(target, source) {
    let result = {...target};
    
    for (let key in source) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            result[key] = deepMerge(result[key] || {}, source[key]);
        } else {
            result[key] = source[key];
        }
    }
    
    return result;
}

let config1 = {
    api: {
        url: "https://api.example.com",
        timeout: 5000
    },
    features: {
        darkMode: true
    }
};

let config2 = {
    api: {
        timeout: 10000,
        retries: 3
    },
    features: {
        notifications: true
    }
};

let mergedConfig = deepMerge(config1, config2);
console.log("Deep merged config:", mergedConfig);

// Example 4: Object path getter/setter
function getObjectPath(obj, path) {
    return path.split('.').reduce((current, key) => current && current[key], obj);
}

function setObjectPath(obj, path, value) {
    let keys = path.split('.');
    let lastKey = keys.pop();
    let target = keys.reduce((current, key) => {
        if (!current[key]) current[key] = {};
        return current[key];
    }, obj);
    target[lastKey] = value;
}

let nestedObj = {
    user: {
        profile: {
            name: "John",
            settings: {
                theme: "dark"
            }
        }
    }
};

console.log("Get path:", getObjectPath(nestedObj, 'user.profile.name'));
setObjectPath(nestedObj, 'user.profile.settings.language', 'en');
console.log("After setting path:", nestedObj.user.profile.settings);