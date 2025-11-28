/*----- app's state (variables) -----*/
let correctAnswers: string[];
let userAnswers: string[];
let userScore: number;
let data = JSON.parse(document.currentScript.getAttribute("data"));


/*----- new types -----*/
type Data = {
  question: string;
  answers: {
    answer_a: string,
    answer_b: string,
    answer_c: string,
    answer_d: string,
    answer_e: string,
    answer_f: string,
  },
  correct_answer: string,
  tags: [{
    name: string
  }]
}

/*----- cached element references -----*/
const questions = document.querySelector<HTMLDivElement>("#questions");
const submitBtn = document.querySelector("#submit-btn") as HTMLButtonElement | null;
const newQuizBtn = document.querySelector("#new-quiz-btn") as HTMLButtonElement | null;
const scoreElem = document.getElementById("score");
const answersElem = document.querySelector<HTMLParagraphElement>("#answers");


/*----- event listeners -----*/
submitBtn?.addEventListener("click", handleSubmitBtn);
newQuizBtn?.addEventListener("click", init);


/*----- functions -----*/
// initialize the quiz
function init() {
  correctAnswers = [];       // no correct answers have been made
  userAnswers = [];          // the user has not made any guesses
  userScore = 0;             // the user doesn't have a score yet

  // start with no questions
  if (questions) questions.innerHTML = "";

  // the score message should not be visible yet
  if (scoreElem) scoreElem.innerHTML = "";

  // the answers should not be visible yet
  if (answersElem) {
    answersElem.innerHTML = "";
    answersElem.style.visibility = "hidden";
  }

  // create the elements from the API data
  createElement(data);
}

// create the elements for the webpage
function createElement(data: any) {
  // iterate over the data and create a new obj with it
  data.forEach((d: Data) => {
    const newData: Data = {
      question: d.question,
      answers: {
        answer_a: d.answers.answer_a,
        answer_b: d.answers.answer_b,
        answer_c: d.answers.answer_c,
        answer_d: d.answers.answer_d,
        answer_e: d.answers.answer_e,
        answer_f: d.answers.answer_f,
      },
      correct_answer: d.correct_answer,
      tags: [{
        name: d.tags[0].name
      }]
    }

    // add the correct answer to each question in teh correct answers array
    correctAnswers.push(newData.correct_answer);

    // create the elements for the data
    const questionElem = document.createElement("p");
    const tagElem = document.createElement('p');
    const labelElem = document.createElement("label");
    const ulistElem = document.createElement("ul");

    // iterate over the answers object in the data object
    for (const [key, val] of Object.entries(newData.answers)) {
      // if there's no answer, then break
      if (val === null) break;

      // create a checkbox element
      const checkbox = document.createElement("input");

      // add a listener to the checkbox
      checkbox.addEventListener("change", () => {
        userAnswers.push(key);
      })

      // set the checkbox type
      checkbox.type = "checkbox";

      // create a list element
      const item = document.createElement("li");

      // combine the checkbox and answer value and append them to the list
      item.append(checkbox, val);
      ulistElem.append(item);
    }

    // create the question and question tag elements
    labelElem.innerHTML = `<strong>${newData.question}</strong>`;
    tagElem.innerHTML = `<i>${newData.tags[0].name}</i>`;

    // add an hr elemnent to separate the questions
    const hr = document.createElement("hr");

    // add all the elements together to create a question board
    labelElem.append(tagElem);
    labelElem.append(ulistElem);
    labelElem.append(hr);
    questionElem.append(tagElem);
    questionElem.append(labelElem);
    questions?.append(questionElem);
  });
}

// check the users answers when the submit button is clicked
function handleSubmitBtn() {
  // iterate over the user answers
  for (let i = 0; i < userAnswers.length; i++) {
    // if the user answer is the same as the correct answers, increment the user's score
    if (userAnswers[i] === correctAnswers[i]) {
      userScore += 5;
    }
  }

  // display the user score
  if (scoreElem) {
    scoreElem.innerHTML = `You scored a ${userScore}! Select 'New Quiz' to take another quiz`;
  }

  // show the correct answers to the questions
  showCorrectAnswers();
}

// show the correct answers
function showCorrectAnswers() {
  // iterate over the correct answers
  correctAnswers.forEach(a => {
    // create a list element
    const item = document.createElement("li");

    // add the correct answer to the list item
    item.append(a);
    
    // show the answers
    if (answersElem) {
      answersElem.append(item);
      answersElem.style.visibility = "visible";
    }
  });
}

// invoke the quiz initialization function
init() 
