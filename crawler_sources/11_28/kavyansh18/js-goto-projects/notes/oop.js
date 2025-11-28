const user = {
    username: 'batman',
    loginCount: 7,
    isGoldMember: true,

    getuserDetails: function () {
        console.log(this);
        console.log(`Username is: ${this.username}`);
    }
}
console.log(user.username);
console.log(user.getuserDetails());

function User(username, loginCount, isGoldMember) {
    this.username = username;
    this.loginCount = loginCount;
    this.isGoldMember = isGoldMember;

    return this
}
const userOne = new User("kavyansh", 5, true)
const userTwo = new User("Aadi", 3, false)
console.log(userOne);


let myName = "kavyansh        ";
Object.prototype.truelength = function () {
    console.log(myName.trim().length);
}
console.log(myName.truelength());


// inheritance

const User = {
    name: "chai",
    email: "chai@google.com"
}

const Teacher = {
    makeVideo: true
}

const TeachingSupport = {
    isAvailable: false
}

const TASupport = {
    makeAssignment: 'JS assignment',
    fullTime: true,
    __proto__: TeachingSupport
}

Teacher.__proto__ = User

// modern syntax
Object.setPrototypeOf(TeachingSupport, Teacher)


//call
function SetUsername(username){
    //complex DB calls
    this.username = username
    console.log("called");
}

function createUser(username, email, password){
    SetUsername.call(this, username) //takes current context from this
   
    this.email = email
    this.password = password
}

const chai = new createUser("chai", "chai@fb.com", "123")
console.log(chai);


