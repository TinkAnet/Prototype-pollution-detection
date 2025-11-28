
// ------------------------------------
//how to convert string into number

// const strNum = "123.3a3"
// console.log();
// const newNum1 = Number(strNum)

// const newNum2 = parseInt(strNum) // ignores letter

// const newNum3 = parseFloat(strNum)
// console.log(newNum3);

// const user = prompt("enter your age")
// console.log(typeof user); //string
// console.log(typeof +user); //number
// -----------------------------------------------------------------------------------------
//DATE CLASS
// console.log(new Date());//current date
//  console.log(new Date().getTime());//current milisecpnds from jan 1 1970

// ---------------------------------------------------
// const today = new Date().getTime()
// const tomorrow = new Date("Oct 27  , 2024").getTime()
// console.log(today);
// console.log(tomorrow);
// const msDiff =  tomorrow - today
// const hours = msDiff / (1000*60*60)
// console.log(hours.toFixed(1));
//  ---------------------------------------------------

//------------------------------------------------------------------------------------------
// console.log(num === 2);
// also check the data type
// ----------------------------------------------------------------------------------------
// Asking user his score and to tell his grade
// let score = prompt("Please enter something:");
// if (score > 0 && score !== isNaN  ) {

//     if(score>50 || score<60)
//     {
//         console.log("  your input score is "+score);
//         score++
//         console.log("  After incrementing your  score is "+score);
//         console.log("your grade is B");
//     }
//     else if(score>=60 && score<=70){
//         console.log("  your input score is "+score);
//         score++
//         console.log("  After incrementing your  score is "+score);
//         console.log("your grade is A");
//     }
//     else if(score >= 71 && score <=80){
//         console.log("  your input score is "+score);
//         score++
//         console.log("  After incrementing your  score is "+score);
//         console.log("your grade is A+");
//     }
//     else if(score>=81 && score<=100){
//         if(score==100){
//             console.log("  your input score is "+score);
//             console.log(" your  score is "+score);
//             console.log("your grade is that you top in class");
//         }
//         else{
//             console.log("  your input score is "+score);
//             score++
//             console.log("  After incrementing your  score is "+score);
//             console.log("your grade is that you top in class");
//         }
//     }
// }
//  else {
//     alert("please enter a valid number .");
// }

// -----------------------------------------------------------------------------------------
// --------------------------------------------LEACTURE 17----------------------------------
// const tinderUser=new Object()//singelton obj
// const tinderUser={}//non singleton obg
// tinderUser.id="123abc"
// tinderUser.name="yumna"
// tinderUser.isLoggedIn=false
// console.log(tinderUser);

// const regularUser={
//     email:"yumna@gmail.com",
//     fullName:{
//         userfullname:{
//             firstName:"yumna",
//             lastName:"nasir"
//         }
//     }
// }
// console.log(regularUser.fullName.userfullname.firstName);

// const obj1={1:"a" , 2:"b"}
// const obj2={1:"c" , 2:"d"}
// const obj3=Object.assign({},obj1,obj2)
// const obj3={...obj1,...obj2}//spread operator
// console.log(obj3);

// const users=[
//     {
//         id:1,
//         email:"yumna@gmail"
//     },
//     {
//         id:1,
//         email:"yumna@gmail"
//     }
// ]
// users[1].email
// console.log(tinderUser);
// console.log(Object.keys(tinderUser));
// console.log(Object.values(tinderUser));
// console.log(Object.entries(tinderUser));

// console.log(tinderUser.hasOwnProperty('isLoggedIn'));

// --------------------------------------------LEACTURE 18----------------------------------
// objects json formatter

// const course = {
//     coursename: "javascript",
//     price:"999",
//     courseInstructor:"hitesh"
// }
// -----object sestructure-------
// course.instructor //not a good way
// const{courseInstructor}=course
// console.log(courseInstructor);
// // or
// const{courseInstructor:instructor}=course
// console.log(instructor);

// const navbar = ({company})=>{//destructuring
// }
// navbar(company="hitesh")
// -------------------------- API-------------------
// API in object
// {
//     "name":"hitesh",
//     "coursename":"js",
//     "price":"free"
// }

//API in array
// [
//     {},
//     {}
// ]

// ---------------------------------------------------LEACTURE 19----------------------------------------
//FUNCTIONS AND PARAMETER


let myName = "yumna"

function myFunction(parameter1,parameter2) {

    let num1 = 5
    if (num1== 5) {
        let myName =  "qurat"
        console.log(myName);
    }
}

console.log(myName);
myFunction()




// syntax
// function myFunction(parameter1,parameter2) {

    // console.log("yumna");

    // in function there is always a return value and 
    // if you dont define any value in return then it will return 
    // undefined by default
// }

// myFunction(parameter1,parameter2)         //calling out A FUNCTION

// function greetUser(myName){ //parameters
//    console.log("hello",myName);
// }
// greetUser("yumna")

// function add(num1,num2){ //parameters
//     a=num1+num2
//     return a;
// }
// const Result=add(2,2); //arguments
// console.log("Result",Result);

// function loginUserMessage(username){
//     if(username === undefined){
//         console.log("please enter a username");
//         return

//     }
//     return `${username} just logged in`
// }
// console.log(loginUserMessage("hitesh"));
// console.log(loginUserMessage());

// --------------------------------------------LEACTURE 20----------------------------------
//rest operator/spread
// 1
// function canculateCartPrice(...num1){
//         return num1
// }
// console.log(canculateCartPrice(200,400,500));

// 2
// anyobject is because function dont know whether api is coming or object is coming
// const user={
//     username:"yumna",
//     prices:999
// }
// function handleObject(anyObject){
//     console.log(`Username is ${anyObject.username} and price is${anyObject.price}`);
// }
// // handleObject(user)
// //direct passing of obj
// handleObject({
//     username:"hitesh",
//     price:199
// })

// 3
//passing of aaray in function
// const myNewArray = [200,400,100,600]
// function returnSecondValue(getArray){
//     return getArray[1]
// }
// console.log(returnSecondValue(myNewArray));

// --------------------------------------------LEACTURE 21----------------------------------
//scope
// we can access var out of the scope and thats the problem
// cant access let and const

// --------------------------------------------LEACTURE 22----------------------------------
// 1
// function one(params) {
//     const username="omer"

//     function two(params) {
//         const website="youtube"
//         console.log(username);
//     }
//     // console.log(website);//cant access
//     two()
// }
// one()

// 2
// if (true) {
//     const username="ayesha"
//     if(username==="ayesha")
//     {
//         const website = "github"
//         console.log(username+website);
//     }
// }

//3

// console.log(addone(2));//can access from here too
// function addone(num) {
//     return num+1
// }
// console.log(addone(2));

// or

// console.log(addtwo(2));//cant access from here
// const addtwo=function (num) { //function/expression
//     return num+2
// }
// console.log(addtwo(2));

// --------------------------------------------LEACTURE 23----------------------------------
//arrow function

// const user ={
//     username:"hitesh",
//     price:999,
//     welcomemsg:function (params) {
//         console.log(`${this.username},welcome to website`);
//         console.log(this);
//     }
// }
// user.welcomemsg()//if i make this a comment and run below command
// console.log(this);//now it will give {}

// 2
// --------------------------------------normal function
// const chai1=function(){

// }
// -------------------------------------Basic arrow function =()=>{}

// const addTwo = (n1,n2)=>     n1+n2          //this is fine implicit return
// const addTwo = (n1,n2)=>     (n1+n2)        //when using () no need to use return keyword
// const addTwo = (n1,n2)=>{                   //explicit return
//     return n1+n2
// }
// const a =addTwo(1,1)
// console.log(a);

// --------------------------------------------LEACTURE 24----------------------------------
// IIFE normal function
// (function chai(params) {
//     console.log("DB CONNECTED");
// }) ();                          //this semicolon is must in between 2 iife

// ----------------------------IIFE arrow function
// ( chai2 = () =>{
//     console.log("DB CONNECTED 2");
// }) ();

// ---------------------------------name IIFE
// ( chai2 = (name) =>{
//     console.log(`DB CONNECTED 2 ${name}`);
// }) ('yumna');

// ---------------------------------unname IIFE
// ((name) =>{
//     console.log(`DB CONNECTED 2 ${name}`);
// }) ('yumna');

// --------------------------------------------LEACTURE 25--------------------------------
//callstack + execution context

// JavaScript Execution context
// global EC =>this
// Functinal EC
// Eval EC

// Memory Creation Phase
// Ececution Phase

// --------------------------------------------LEACTURE 26--------------------------------
//CONTROL FLOW/LOGIC FLOW
// if(2 === "2") true
// --------------------------------------------LEACTURE 27--------------------------------
//loops

// --------------------------------------------LEACTURE 28--------------------------------

// --------------------------------------------LEACTURE 29--------------------------------
//for of => will not work on objects

// obj in arrays
// [{},{},{}]

// const arr = [1,2,3,4,5]
// for (const num of arr) {
//             console.log(num);
// }

// const greetings = "hello world"
// for (const greet of greetings) {
//     console.log(`each char is ${greet}`);

// }

// --------------------------------------------LEACTURE 30--------------------------------
//MAP

// const myNum = [1,2,3,4,5,6,7,8,9,10]
// const newNums=myNum.map((num)=>num+10)
// console.log(newNums);

// const map = new Map()
// map.set('IN','India')
// map.set('US','United States Of America')
// console.log(map);

// const map = new Map()
// map.set('IN','India')
// map.set('US','United States Of America')
// for (const [key,value] of map) {
//     console.log(key, ':-',value);
// }

// const myObject = {
//     'game1':'NFS',
//     'game2':'Spiderman'
// }
// for of wont work on obj//
// for (const [key,value] of myObject) {
//     console.log(key,'-:',value);
// }

// const myObject = {
//     js:'javascript',
//     cpp:'c++'
// }

// for (const key in myObject) {
//     //    console.log(myObject[key]);
//     console.log(`${key} shortcut is for ${myObject[key]}`);

// }

//------------------------------------FILTER
// 1)
// const myNums = [1,2,3,4,5,6,7,8,9,10]
// const newnum=myNums.filter((num)=>
//         num>4
// )
// console.log(newnum);

// 2)
// const myNums = [1,2,3,4,5,6,7,8,9,10]
// const newnum=myNums.filter((num)=>{
//     return num>4
//     //with curly braces it wil not return without return statement
// })
// console.log(newnum);

// 3)
// const myNums = [1,2,3,4,5,6,7,8,9,10]
// const newnum=myNums.filter((num)=> (num>4) )
// console.log(newnum);

// const Books=[
//     {title:'book one',genre:'Fiction',publish:1981,edition: 2000},
//     {title:'book two',genre:'history',publish:1982,edition: 2001},
//     {title:'book three',genre:'science',publish:1983,edition: 2002},
//     {title:'book four',genre:'tragic',publish:1984,edition: 2003}
// ]
// const userbooks=Books.filter((bk)=>{
//         return bk.genre==='tragic'
// })
// console.log(userbooks);

// -----------------chaining

// const myNum = [1,2,3,4,5,6,7,8,9,10]
// const newNums=myNum.map((num)=> num * 10)
//                     .map((num)=>num + 1)
//                     .filter((num)=> num>=40)
// console.log(newNums);

// ----------------REDUCE
// 1)
// const myNum=[1,2,3]
// const myTotal=myNum.reduce(function(acc,currval) {
//     console.log(`acc:${acc} and currval: ${currval}`);

//     return acc+currval},3)
//     console.log(myTotal);

// 2)
// const myNum=[1,2,3]
// const myTotal=myNum.reduce((acc,currval) => acc+currval,3)
//     console.log(myTotal);

// const ShoppingCart = [
//     {
//         itemName:"js course",
//         price:100
//     },
//     {
//         itemName:"py course",
//         price:200
//     },
//     {
//         itemName:"cpp course",
//         price:400
//     },
// ]
// const money =ShoppingCart.reduce((acc,item)=>acc+ item.price,0)
// console.log(money);

// --------------------------------------------LEACTURE 31--------------------------------
// DOM(document obj model)

// --------------------------------------------LEACTURE 32--------------------------------
//DOM
{
  /* <div class="bg-black">
        <h1 id="title" class="heading">DOM LEARNING</h1>
        <p>Lorem ipsum s ods consequatur qui iusto totam!</p>
    </div> */
}

// --------------------------------------------LEACTURE 33--------------------------------
//HOW TO SELECT DOCUMENT

{
  /* <div class="parent">
            <div class="day">monday</div>
            <div class="day">tuesday</div>
            <div class="day">wednesday</div>
            <div class="day">thursday</div>
            <div class="day">friday</div> */
}
//     </div>

//  <script>
//     // const parent = document.querySelector('.parent')
//     // console.log(parent);
//     // console.log(parent.children[0]);
//     {/* // console.log(parent.children[0].innerHTML); */}

//     {/* // for (let i = 0; i < parent.children.length; i++) { */}
//     //     console.log(parent.children[i].innerHTML);
//     //     parent.children[1].style.color="orange"
//     // }

//     //same
//     // console.log(parent.children[0]);
//     // console.log(parent.firstElementChild);
//     // console.log(parent.lastElementChild);

//     // const dayOne=document.querySelector('.day')
//     // console.log(dayOne);
//     // console.log(dayOne.parentElement);
//     // console.log(dayOne.nextElementSibling);

//     // console.log("nodes;-", parent.childNodes);

// -----------------------------------HOW TO CREATE AN ELEMENT
// const div = document.createElement('div')
// console.log(div);
// div.className="divider"
// div.id=Math.round(Math.random()*10+1)
// div.id="ruler"
// div.innerHTML="my firset javascript code" //no
// const text=document.createTextNode("my firset javascript code") //yes
// div.appendChild(text)
// div.setAttribute("title","chai or code")
// div.style.backgroundColor="purple"
// div.style.color="white"
//-------attaching div to body--------
// document.body.appendChild(div)

// const h1 = document.createElement('h1')
// console.log(h1);

// --------------------------------------------LEACTURE 34--------------------------------
//EDIT AND REMOVE ELEMENTS IN DOM

{
  /* <ul class="language">
            <li>javascript</li>
        </ul> */
}
// ----------------------------

// function addLanguage(language){
//     const li=document.createElement('li')
//     li.innerHTML=`${language}`
//     document.querySelector('.language').appendChild(li)
// }
// addLanguage("ruby")

// -------------------------------OPTIMIZE APPROACH-------
// function addOPTILanguage(language) {
//     const li=document.createElement('li')
//     const text=document.createTextNode(language)
//     li.appendChild(text)
//     //or
//     // li.appendChild(document.createTextNode(language))
//     document.querySelector('.language').appendChild(li)
// }
// addOPTILanguage("golang")
// addOPTILanguage("python")
// ------------------------------------IF I HAVE TO CHANGE PYTHON INTO C++(best)

// 1)select the element you want to change
// 2)create a new element
// 3)change the text of that new element
// 4)replave with the element you select first
// const secLang=document.querySelector("li:nth-child(2)")
// secLang.innerHTML="c++"no
// const newli=document.createElement('li')
// newli.textContent="mojo"
// secLang.replaceWith(newli)
// console.log(secLang);

// 2)
//remove last element=>python
// const lastLang=document.querySelector('li:last-child')
// lastLang.remove()

// --------------------------------------------LEACTURE 35--------------------------------
// -----------------------------PROJECT------------------------------------------------------

// --------------------------------------------LEACTURE 36--------------------------------
//EVENTS
// =>event propogation
// =>bubbling

// ----------------------------------------------------------index-----------------------------------------
{
  /* <h2>Amazing images</h2>
        <div>
        <ul id="images">
            <li><img src="img/pexels-dejiprince-28231061.jpg"  id="girl"></li>
            <li><img src="img/pexels-miami302-26793646.jpg"  id="dog" alt=""></li>
            <li><img src="img/pexels-njeromin-20177407.jpg" id="plane"alt=""></li>
            <li><img src="img/pexels-ruxandra-scutelnic-1470184397-28259733.jpg" id="cake"alt=""></li>
            <li><img src="img/pexels-wwarby-21533286.jpg" id="bridge"alt=""></li>
            <li><a style="color: rgb(73, 213, 231);" href="https://www.google.com/" id="google">google</a></li>
        </ul>
        </div> */
}
// ----------------------------------------------------------index-----------------------------------------

//document.getElementById('images').addEventListener('onclick', function name(params) {},false)
// capturing start to end true
//bubbling down to upward false
// document.getElementById('images').addEventListener('click', function (e) {
//     console.log("clicked inside ul");
// },false)

// document.getElementById('plane').addEventListener('click', function (e) {
//     console.log("clicked owl");
//     e.stopPropagation()
//     // ye for ex just slick owl print krega not
// },false)

// document.getElementById('google').addEventListener('click',function (e) {
//     e.preventDefault()
//     e.stopPropagation()
//     console.log("google clicked");
// },false)

// --------------------------
// document.querySelector('#images').addEventListener('click',function(e){
//     // console.log(e.target);will give you just images
//     // console.log(e.target.parentNode); //will give you just li
//     console.log(e.target.tagName); //will give you just li
//     if (e.target.tagName === 'IMG') {
//         // removeIt.parentNode.removeChild(removeIt)  //best way
//         let removeIt= e.target.parentNode
//         removeIt.remove() //ok
//     }
// },false)

// --------------------------------------------LEACTURE 37--------------------------------
//ASYNC
// javascrip is synchronous(line by line execution)
//single threaded language

// => BLOCKING CODE
//    block the flow of program
//    read file sync

// => NON BLOCKING CODE
//    do not block the execution
//    read file async

// --------------------------------------------LEACTURE 38--------------------------------
// PROJECTS WITH ASYNC JS

// --------------------------------------------LEACTURE 39--------------------------------
// API request and V8 engine
// JSON FORMATTER

// --------------------------------------------LEACTURE 40--------------------------------
// Promise syntax
// const promiseOne=new Promise((resolve, reject) => {})
// promiseThree.then().catch()

//what does this resolve and reject doing
// ---------------------------------------------1
// const promiseOne=new Promise((resolve, reject) => {
//     // Do an async task
//     //DB Calls, cryptography,network
//     setTimeout(() => {
//         console.log("async task is completed");
//         resolve()
//     }, 1000);

//     })
//     //it has a direction connection with resolve
//     // but we did not connect the resolve with this the so connect to this to promise
//     //we write resolve() in promise
//     promiseOne.then(()=>{
//         console.log("promise consumed");

//     })

// ---------------------------------------------2

// new Promise((resolve, reject) => {
//         setTimeout(() => {
//             console.log("async task  2 is completed");
//             resolve()
//         }, 1000);

//         }).then(()=>{
//             console.log("Async 2 resolved");
//         })

// ---------------------------------------------3

// const promiseThree=new Promise((resolve, reject) => {
//     setTimeout(() => {

//         resolve({userame:"chai",email:"chai@example.com"})
//     }, 1000);
//     })
//     promiseThree.then((user)=>{
//         console.log(user);

//             })
// // ---------------------------------------------4-------use case of reject

// const promiseFour=new Promise((resolve, reject) => {
//     setTimeout(() => {

//         let error =false
//         if (!error) {
//             resolve({username:"hitesh",password:"123"})
//         }
//         else{
//             reject("ERROR: something is wrong ")
//         }
//     }, 1000);
//     })
//     // chaining
//     const username=promiseFour
//             .then((user)=>{
//                 console.log(user)
//                 return user.username
//             }).then((username)=>{
//                 console.log(username);

//             }).catch((error)=>{
//                 console.log(error);

//             }).finally(()=>{console.log("promise is either resolved or rejected");
//             })
// ----------------------------------------------

// const Num = 10.31646
// console.log(Num);
// console.log(Num.toFixed(2));

// --------------------------------------------------
// DATE
// console.log(new Date());
// console.log(new Date().getDay());
// console.log(new Date().getMonth()+1); 
// ----------------------------------------------------
// Define a function that you want to run every second
// function myFunction() {
//   console.log("This message is logged every second.");
// }

// // Use setInterval to call the function every 1000 milliseconds (1 second)
// const intervalId = setInterval(myFunction, 1000);

// // Optional: To stop the interval after a certain time, you can use clearInterval
// setTimeout(() => {
//   clearInterval(intervalId);
//   console.log("Interval cleared.");
// }, 10000); // Stops the interval after 10 seconds

// ---------------------------------------------


// const promiseFive=new Promise((resolve, reject) => {
//     setTimeout(() => {

//         let error =true
//         if (!error) {
//             resolve({username:"javascript",password:"123"})
//         }
//         else{
//             reject("ERROR: JS is wrong ")
//         }
//     }, 1000);
//     })
// async function consumepromiseFive(){
//     const response=await promiseFive
//     console.log(response);

// }
// const consumepromiseFive = async () => {
//     try {
//         const response = await promiseFive;
//         console.log(response);
//     } catch (error) {
//         console.log(error);

//     }
// };
// consumepromiseFive()

// -------------------------------------or -------------------------------------
// chaining
//     const username=promiseFive
//             .then((user)=>{
//                 console.log(user)
//                 return user.username
//             }).then((username)=>{
//                 console.log(username);

//             }).catch((error)=>{
//                 console.log(error);

//             }).finally(()=>{console.log("promise5 is either resolved or rejected");
//             })

// // --------------------try and catch format
//     const getAllUser = async()=>{
//         try {
//             const response=await fetch('https://jsonplaceholder.typicode.com/user')
//             const data=await response.json()
//             console.log(data);
//         } catch (error) {
//             console.log("error",error);

//         }
//     }
//     // getAllUser()

//     fetch('https://jsonplaceholder.typicode.com/user')
//     .then((response)=>{
//         return response.json()
//     })
//     .then((data)=>{
//         console.log(data);

//     })
//     .catch((error)=>{
//         console.log(error);

//     })

// --------------------------------------------LEACTURE 41--------------------------------
// FETCH

// --------------------------------------------LEACTURE 42--------------------------------
// OOP

// --------------------------------------------LEACTURE 43--------------------------------
//prototype
//gave the access of this and new keyword

// in prototype we get access of some methods
// we can change methods in protoype of our own

// function multiplyBy5(num) {
//      return num*5
// }
// multipleBy5.power = 2

// console.log(multipleBy5(5));
// console.log(multipleBy5.power);
// console.log(multipleBy5.prototype); //empty{}

// function createUser(username,score) {
//     this.username=username
//     this.score=score
// }

// createUser.prototype.increment=function () {
//     this.score++;
// }
// createUser.prototype.printMe=function () {
//     console.log(`score is ${this.score}`);
// }

// const chai = new createUser("chai",25)
// const tea = new createUser("tea",250)

// chai.printMe()

// Here's what happens behind the scenes when the new keyword
//  is used:

// A new object is created: The new keyword initiates the
// creation of a new JavaScript object.

// A prototype is linked: The newly created object gets linked to the prototype
// property of the constructor function. This means that it has
//  access to properties and methods defined on the constructor's prototype.

// The constructor is called: The constructor function is
//
// called with the specified arguments and this is bound to the newly created object.
// If no explicit return value is specified from the constructor, JavaScript assumes this, the newly created object,
//  to be the intended return value.

// The new object is returned: After the constructor function has been
// called, if it doesn't return a non-primitive value (object, array, function, etc.),
//  the newly created object is returned.
// ---------------------------------------

// let myName = "hitesh     "
// let mychannel = "chai     "

// console.log(myName.trueLength);

// let myHeros = ["thor", "spiderman"]

// let heroPower = {
//     thor: "hammer",
//     spiderman: "sling",

//     getSpiderPower: function(){
//         console.log(`Spidy power is ${this.spiderman}`);
//     }
// }

// Object.prototype.hitesh = function(){
//     console.log(`hitesh is present in all objects`);
// }

// Array.prototype.heyHitesh = function(){
//     console.log(`Hitesh says hello`);
// }

// heroPower.hitesh()
// myHeros.hitesh()

// myHeros.heyHitesh() //accessible cause this is an array
// heroPower.heyHitesh() //not accessible cause this is an array

// inheritance

// const User = {
//     name: "chai",
//     email: "chai@google.com"
// }

// const Teacher = {
//     makeVideo: true
// }

// const TeachingSupport = {
//     isAvailable: false
// }

// const TASupport = {
//     makeAssignment: 'JS assignment',
//     fullTime: true,
//     __proto__: TeachingSupport
// }

// Teacher.__proto__ = User

// // modern syntax
// Object.setPrototypeOf(TeachingSupport, Teacher)

// let anotherUsername = "ChaiAurCode     "

// String.prototype.trueLength = function(){
//     console.log(`${this}`);
//     console.log(`True length is: ${this.trim().length}`);
// }

// anotherUsername.trueLength()
// "hitesh".trueLength()
// "iceTea".trueLength()

// --------------------------------------------LEACTURE 44--------------------------------
// Call and this in javascript |

// function SetUsername(username){
//     //complex DB calls
//     this.username = username
//     console.log("called");
// }

// function createUser(username, email, password){
//     SetUsername.call(this.username)

//     this.email = email
//     this.password = password
// }

// const chai = new createUser("chai", "chai@fb.com", "123")
// console.log(chai);

// --------------------------------------------LEACTURE 45--------------------------------
// Class constructor and static

// class User {
//   constructor(username, email, password) {
//     this.username = username;
//     this.email = email;
//     this.password = password;
//   }
//   encryptPassword() {
//     return `${this.password}abc`;
//   }
//   changeUsername() {
//     return `${this.username.toUpperCase()}`;
//   }
// }
// const chai = new User("yumna", "yumna@gmail.com", "123");
// console.log(chai.encryptPassword());
// console.log(chai.changeUsername());

// -------------------bts--------
// function User(username, email, password){

//         this.username = username;
//         this.email = email;
//         this.password = password;
// }

// User.prototype.encryptPassword  = function () {
//         return `${this.password}abc`;
// }
// User.prototype.changeUsername  = function () {
//     return `${this.username.toUpperCase()}`;
// }

// const tea=new User("tea","tea@gmail.com","123")
// console.log(tea.encryptPassword());
// console.log(tea.changeUsername());

// const chai=new User("chai","chai@gmail.com","123")
// console.log(chai.encryptPassword());
// console.log(chai.changeUsername());

// -----------------------------------

// class User{
//     constructor(username){
//         this.username=username
//     }
//     LogMe(){
//         console.log(`Username is ${this.username}`);
        
//     }
// }
// class Teacher extends User{
//     constructor(username,email,password){
//             super(username)
//             this.email=email
//             this.password=password
//     }
//     addCourse(){
//         console.log(`new course is added by ${this.username}`);
        
//     }
// }
// const chai = new Teacher("chai","chai@gmail.com","123")
// chai.addCourse()
// console.log(chai instanceof User); //true

// -----------------------------------------
// static prop

// class User {
//     constructor(username){
//         this.username=username
//     }
//     LogMe(){
//         console.log(`Username is ${this.username}`);        
//         }
//         //static will stop
//      creatId(){
//         return `123`
//     }
// }
// const hitesh  = new User("hitesh")
// // console.log(hitesh.creatId());

// class Teacher extends User {
//     constructor(username,email){
//         super(username)
//         this.email = email
//     }
// }
// const yum = new Teacher("yumna","email@")
// yum.LogMe()
// console.log(yum.creatId());
// if you assign the value static to createId you can not access it




// --------------------------------------------LEACTURE 46--------------------------------
// Bssind in javascript

//for bind we need html file
// ----------------------------
{/* <button>Button Clicked</button> */}
// -----------------------------
// class React {
//     constructor(){
//         this.library = "React"
//         this.server = "https://localhost:300"

//         //requirement
//         document
//             .querySelector('button')
//             .addEventListener('click', this.handleClick.bind(this))

//     }
//     handleClick(){
//         console.log("button clicked");
//         console.log(this.server);
//     }
// }

// const app = new React()


// --------------------------------------------LEACTURE 47--------------------------------
//told us about some hidden things
// const discriptor=Object.getOwnPropertyDescriptor(Math,"PI")
// console.log(discriptor);

// const chai = {
//     name: "ginger chai",
//     price: 25,
//     isAvailable :true
// }
// console.log(Object.getOwnPropertyDescriptor(chai));
// will print undefined cause  this getOwnPropertyDescriptor
// can be apply on properties or methods and chai is an object
// console.log(Object.getOwnPropertyDescriptor(chai,"name"));
// Object.defineProperty(chai,'name',{
//     writable:false
// })
// console.log(Object.getOwnPropertyDescriptor(chai,"name"));


// --------------------------------------------LEACTURE 48--------------------------------
// class User {
//     constructor(email, password){
//         this.email = email;
//         this.password = password
//     }

//     get email(){
//         return this._email.toUpperCase()
//     }
//     set email(value){
//         this._email = value
//     }
//     // .-email property is private now

//     get password(){
//         return `${this._password}hitesh`
//     }

//     set password(value){
//         this._password = value
//     }
// }

// const hitesh = new User("h@hitesh.ai", "abc")
// console.log(hitesh.email);
 //------------------------------------------------------------------------------------------------
 function User(email, password){
    this._email = email;
    this._password = password

    Object.defineProperty(this, 'email', {
        get: function(){
            return this._email.toUpperCase()
        },
        set: function(value){
            this._email = value
        }
    })
    Object.defineProperty(this, 'password', {
        get: function(){
            return this._password.toUpperCase()
        },
        set: function(value){
            this._password = value
        }
    })

}

const chai = new User("chai@chai.com", "chai")

console.log(chai.email);
// --------------------------------------------LEACTURE 49--------------------------------
// --------------------------------------------LEACTURE 50--------------------------------
// --------------------------------------------LEACTURE 51--------------------------------
