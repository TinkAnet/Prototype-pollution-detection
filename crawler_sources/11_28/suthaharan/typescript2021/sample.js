"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
var message = "Hello World!";
console.log(message);
// let vs const
var aa = 10;
var title = "Sample Program";
// // cannot redeclare block level variable. Below statement is invalid
// let a = 20; 
// // cannot assign new value to title as it is constant
// title = "New title";
// JS Types
var name = "Don";
var departmentId = 100;
var isEmployed = true;
var description = "Employee name is " + name + " belonging to Dept " + departmentId + ".\nStatus of Employment: " + isEmployed;
console.log(description);
// Array declaration
var departments = ["IT", "Sales", "HR"];
var divisions = ["Sales1", "Sales2"];
// Tuples: For values of mixed types
var employee = ["Adam", 28];
// Enums
var race;
(function (race) {
    race[race["asian"] = 3] = "asian";
    race[race["african"] = 4] = "african";
    race[race["caucasian"] = 5] = "caucasian";
})(race || (race = {}));
;
var myrace = race.african;
console.log(myrace);
// Any type
var newVariable;
newVariable = "Welcome to my Club!";
newVariable.toUpperCase();
console.log(newVariable);
// unknown type
var newVariable2;
newVariable2 = "Welcome to my Club!";
newVariable2.toUpperCase();
console.log(newVariable2);
//
var a;
a = 10;
a = true;
var b = 20;
//b=true; // will not work
var myType;
myType = 10;
myType = true;
// simply multiply
function multiply(a, b) {
    return a * b;
}
// Multiply with optional parameters
function multiply2(a, b) {
    if (b) {
        return a * b;
    }
    else {
        return a;
    }
}
// Multiply with default assignment
function multiply3(a, b) {
    if (b === void 0) { b = 10; }
    return a * b;
}
var person = /** @class */ (function () {
    function person(n, t) {
        this.name = n;
        this.title = t;
    }
    person.prototype.greet = function () {
        console.log("Welcome " + this.title + "." + this.name + "!");
    };
    return person;
}());
var p = new person('Van', 'Mr');
var m = p.greet();
var customer = /** @class */ (function (_super) {
    __extends(customer, _super);
    function customer(n, t, l, y) {
        var _this = _super.call(this, n, t) || this;
        _this.loyaltymember = l;
        _this.year = y;
        return _this;
    }
    customer.prototype.isLoyal = function () {
        if (this.loyaltymember) {
            console.log(this.name + " is a loyal member since " + this.year);
        }
        else {
            console.log(this.name + " is not a loyal member");
        }
    };
    return customer;
}(person));
var c = new customer('Van', 'Mr', true, 1976);
c.greet();
c.isLoyal();
