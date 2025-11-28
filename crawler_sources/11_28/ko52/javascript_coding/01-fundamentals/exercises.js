// JavaScript基礎 - 練習問題

console.log('=== JavaScript基礎 練習問題 ===');

/* 
練習問題を解いてJavaScriptの基礎を固めましょう！
各問題の解答は下部に用意されています。
まず自分で考えてから解答を確認してください。
*/

console.log('\n--- 問題1: 変数とデータ型 ---');
/*
問題1: 以下の変数を適切な方法で宣言し、初期値を設定してください
- ユーザー名（変更可能）
- ユーザーの年齢（変更可能）  
- サイト名（変更不可）
- ユーザーがログインしているかの状態（変更可能）

そして、それぞれのデータ型をtypeofで確認してください。
*/

// ここに回答を書いてください


console.log('\n--- 問題2: 演算子 ---');
/*
問題2: 以下の計算を行う関数を作成してください
- 2つの数値を受け取り、四則演算の結果をオブジェクトで返す関数
- 返すオブジェクトは { add, subtract, multiply, divide } の形式

例: calculate(10, 2) → { add: 12, subtract: 8, multiply: 20, divide: 5 }
*/

function calculate(a, b) {
  // ここに実装してください
}

// テスト
// console.log(calculate(10, 2));


console.log('\n--- 問題3: 制御構文 ---');
/*
問題3: 成績判定関数を作成してください
- 点数（0-100）を受け取る
- 90以上: 'A', 80以上: 'B', 70以上: 'C', 60以上: 'D', 60未満: 'F'
- 無効な点数の場合は '無効な点数' を返す
*/

function getGrade(score) {
  // ここに実装してください
}

// テスト
// console.log(getGrade(95)); // 'A'
// console.log(getGrade(75)); // 'C'
// console.log(getGrade(50)); // 'F'


console.log('\n--- 問題4: 配列操作 ---');
/*
問題4: 数値配列を操作する関数群を作成してください
*/

// 4-1: 配列の偶数のみを抽出する関数
function getEvenNumbers(numbers) {
  // ここに実装してください
}

// 4-2: 配列の各要素を2乗した新しい配列を返す関数
function squareNumbers(numbers) {
  // ここに実装してください
}

// 4-3: 配列の合計値を計算する関数
function sumArray(numbers) {
  // ここに実装してください
}

// テスト
// const testArray = [1, 2, 3, 4, 5, 6];
// console.log(getEvenNumbers(testArray)); // [2, 4, 6]
// console.log(squareNumbers(testArray));  // [1, 4, 9, 16, 25, 36]
// console.log(sumArray(testArray));       // 21


console.log('\n--- 問題5: オブジェクト操作 ---');
/*
問題5: 学生管理システムを作成してください
*/

// 5-1: 学生オブジェクトを作成する関数
function createStudent(name, age, subjects) {
  // name: 文字列, age: 数値, subjects: 配列
  // 学生オブジェクトを返してください
  // 例: { name: '太郎', age: 20, subjects: ['数学', '英語'], getId: function() {...} }
  // getIdメソッドは "name_age" 形式の文字列を返す
}

// 5-2: 学生の配列から特定の科目を履修している学生を見つける関数
function findStudentsBySubject(students, subject) {
  // ここに実装してください
}

// テスト
// const student1 = createStudent('太郎', 20, ['数学', '英語']);
// const student2 = createStudent('花子', 19, ['英語', '歴史']);
// const students = [student1, student2];
// console.log(findStudentsBySubject(students, '英語')); // 両方の学生


console.log('\n--- 問題6: 高度な問題 ---');
/*
問題6: ショッピングカート機能を実装してください
*/

function createShoppingCart() {
  // プライベートな商品配列
  let items = [];
  
  return {
    // 商品を追加（id, name, price, quantity）
    addItem: function(id, name, price, quantity = 1) {
      // ここに実装してください
    },
    
    // 商品を削除
    removeItem: function(id) {
      // ここに実装してください
    },
    
    // 商品の数量を変更
    updateQuantity: function(id, quantity) {
      // ここに実装してください
    },
    
    // 合計金額を計算
    getTotal: function() {
      // ここに実装してください
    },
    
    // 全商品を取得
    getItems: function() {
      // ここに実装してください
    }
  };
}

// テスト
// const cart = createShoppingCart();
// cart.addItem(1, 'りんご', 100, 3);
// cart.addItem(2, 'バナナ', 80, 2);
// console.log(cart.getItems());
// console.log(cart.getTotal()); // 460


console.log('\n--- 解答例 ---');
console.log('解答を確認したい場合は、01-fundamentals-answers.js を参照してください');


// =============================================================================
// 追加練習問題
// =============================================================================

console.log('\n=== 追加練習問題 ===');

/*
問題7: FizzBuzz問題
1から100までの数字を出力し、3の倍数の時は"Fizz"、5の倍数の時は"Buzz"、
3と5の両方の倍数の時は"FizzBuzz"を出力する関数を作成してください。
*/

function fizzBuzz(limit = 100) {
  // ここに実装してください
}

/*
問題8: 回文判定
文字列が回文（前から読んでも後ろから読んでも同じ）かどうかを判定する関数を作成してください。
大文字小文字は区別しません。
*/

function isPalindrome(str) {
  // ここに実装してください
}

/*
問題9: 単語カウンター
文字列内の各単語の出現回数をカウントするオブジェクトを返す関数を作成してください。
*/

function countWords(text) {
  // ここに実装してください
}

/*
問題10: 深いオブジェクトのマージ
2つのオブジェクトを深くマージする関数を作成してください。
*/

function deepMerge(obj1, obj2) {
  // ここに実装してください
}

console.log('\n練習問題は以上です！');
console.log('自分なりに解いてから、解答例を確認してください。');
