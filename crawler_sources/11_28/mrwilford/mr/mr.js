//mr.js © 2023 Michael Wilford. All Rights Reserved.
//https://cdn.jsdelivr.net/gh/mrwilford/mr/mr.js (or mr.min.js)
'use strict';

//determine where this code is executing
const _isClient  = !!globalThis.window, _isServer = !_isClient;

//auto-initialize on client
if(_isClient) document.addEventListener('DOMContentLoaded', _ => mrInit())

/** Initialize the mr library.
 * @param {*} [callerGlobalThis] Defaults to ``globalThis`` where all functionality is attached.
 * @returns {*} The given ``callerGlobalThis`` with the new functionality attached.
 */
function mrInit(callerGlobalThis=globalThis){
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region CONSTANTS

  const _backend   = getScriptUrl(`AKfycbyn2rf6Uk2aIL-ViBd81431n8XhwKe8M6pHZA70clG-ej3r97bkTdBV6Ehhzu-e1L6R`);
  const _isBackend = _isServer && callerGlobalThis===globalThis, _isFrontend = _isServer && !_isBackend;
  const asciiA     = 'A'.charCodeAt(0);//65
  const nbsp       = '\xa0', nbtab = nbsp.repeat(4);
  const msPerSec   = 1000         , msToSec  = ms  => ms /msPerSec , secToMs  = sec => sec*msPerSec ;
  const msPerMin   = 1000*60      , msToMin  = ms  => ms /msPerMin , minToMs  = min => min*msPerMin ;
  const msPerHr    = 1000*60*60   , msToHr   = ms  => ms /msPerHr  , hrToMs   = hr  => hr *msPerHr  ;
  const msPerDay   = 1000*60*60*24, msToDay  = ms  => ms /msPerDay , dayToMs  = day => day*msPerDay ;
  const secPerMin  =      60      , secToMin = sec => sec/secPerMin, minToSec = min => min*secPerMin;
  const secPerHr   =      60*60   , secToHr  = sec => sec/secPerHr , hrToSec  = hr  => hr *secPerHr ;
  const secPerDay  =      60*60*24, secToDay = sec => sec/secPerDay, dayToSec = day => day*secPerDay;
  const minPerHr   =         60   , minToHr  = min => min/minPerHr , hrToMin  = hr  => hr *minPerHr ;
  const minPerDay  =         60*24, minToDay = min => min/minPerDay, dayToMin = day => day*minPerDay;
  const hrPerDay   =            24, hrToDay  = hr  => hr /hrPerDay , dayToHr  = day => day*hrPerDay ;
  const PUBLIC     = Symbol('PUBLIC'), PRIVATE = Symbol('PRIVATE');//do not export PRIVATE!
  const TIMESUP    = Symbol('TIMESUP');

  //#endregion CONSTANTS
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region SETTINGS
  const Settings               = {}   , Defaults                   = {}   ;
  Settings.Debug               = true , Defaults.Debug             = true ;
  Settings.Release             = false, Defaults.Release           = false;
  Settings.useBatchGet         = false, Defaults.useBatchGet       = false;
  Settings.warnMemoizeRedefine = false, Defaults.warnRedefinitions = true ;
  //restore defaults
  Settings.reset = () => Object.keys(Defaults).forEach(key => Settings[key] = Defaults[key]);
  //#endregion SETTINGS
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region TYPE CHECKING

  //when using this script as a library, GAS gives it its own set of primitive type 
  //constructors such that "Number != myLib.Number" which means our type checking 
  //system will not work unless we fix the prototype chains
  Number         = callerGlobalThis.Number        ;
  BigInt         = callerGlobalThis.BigInt        ;
  Boolean        = callerGlobalThis.Boolean       ;
  String         = callerGlobalThis.String        ;
  Symbol         = callerGlobalThis.Symbol        ;
  Date           = callerGlobalThis.Date          ;
  Set            = callerGlobalThis.Set           ;
  WeakSet        = callerGlobalThis.WeakSet       ;
  Map            = callerGlobalThis.Map           ;
  WeakMap        = callerGlobalThis.WeakMap       ;
  Function       = callerGlobalThis.Function      ;
  Array          = callerGlobalThis.Array         ;
  Object         = callerGlobalThis.Object        ;
  Error          = callerGlobalThis.Error         ;
  EvalError      = callerGlobalThis.EvalError     ;
  TypeError      = callerGlobalThis.TypeError     ;
  RangeError     = callerGlobalThis.RangeError    ;
  SyntaxError    = callerGlobalThis.SyntaxError   ;
  ReferenceError = callerGlobalThis.ReferenceError;
  URIError       = callerGlobalThis.URIError      ;
  //Object.setPrototypeOf(Object.prototype,callerGlobalThis.Object.prototype);

  /** Get the given variable as a primitive type.
   * @param {*} v
   * @return {*}
   */
  const Primitive = v => v && v.constructor(v);//new Number(5) ⇾ 5
  
  /** Get the given variable as a ``SmallInt``.
   * @param {number|string} v
   * @return {number}
   */
  const SmallInt = v => Number.parseInt(v);
  
  /** Get the given variable as a finite primitive number.
   * @param {number} v
   * @return {number|undefined}
   */
  const Finite = v => is.Finite(v) ? Number(v) : undefined;

  /** Get the given variable as an entries array.
   * ```
   * Entries({ one: 1, two: 2 }); // ⇾ [ [ 'one', 1 ], [ 'two', 2 ] ]
   * ```
   * @param {*} v
   * @return {Array<Array<*>>}
   */
  const Entries = v => Object.entries(v);
  
  /** Get the given variable as an indexed array.
   * ```
   * Indexed({ 0: 'zero', 1: 'one' }); // ⇾ [ 'zero', 'one' ]
   * ```
   * @param {*} v
   * @return {Array<*>}
   */
  const Indexed = v => !v || is(v, Array) ? v : Entries(v).filter(([key]) => is(key, Number));
  
  /** Get the given variable as a key-compatible string or number.
   * @param {*} v
   * @return {string|number}
   */
  const Key = v => 'object'==typeof v ? undefined : Object.keys({ [v]: null })[0];
  
  /** Test or match a string ID.
   * ```
   * $Id.test('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); // ⇾ true
   * 'https://docs.google.com/ABCDEFGHIJKLMNOPQRSTUVWXYZ/edit'.match($Id).pop(); // ⇾ 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
   * ```
   */
  const $Id = /[-\w]{25,}/;

  /** Test or match a trigger ID. */
  const $TriggerId = /\d{19}/;//e.g: 4616076814456607965

  /**
   * Test or match a string URL.
   * ```
   * $Url.test('www.google.com'); // ⇾ true
   * 'www.google.com'.match($Url).pop(); // ⇾ 'www.google.com'
   * ```
   */
  const $Url = /^(?:(?:https?|ftp|smtp):\/\/)?.+$/i;//imperfect
  
  /** Test or match a string path.
   * ```
   * $Path.test('files/temp/todo.txt'); // ⇾ true
   * 'files/temp/todo.txt'.match($Path); // ⇾ [ 'files', 'temp', 'todo.txt' ]
   * ```
   */
  const $Path = /[^\\\/]+/g;
  
  /** Test or match a string email address.
   * ```
   * $Email.test('hi@wilford.dev'); // ⇾ true
   * 'hi@wilford.dev'.match($Email).pop(); // ⇾ 'hi@wilford.dev'
   * ```
   */
  const $Email = /^[^\s\@]+@[^\s\@]+\.[^\s\@]+$/;//imperfect
  
  /** Test or match a string range address.
   * ```
   * $Range.test("'Sheet1'!$A$2:B"); // ⇾ true
   * "'Sheet1'!$A$2:B".match($Range).pop(); // ⇾ '$A$2:B'
   * ```
   */
  const $Range = /^\$?(?:[a-z]+|[0-9]+|[a-z]+\$?[0-9]+)(?::\$?(?:[a-z]+|[0-9]+|[a-z]+\$?[0-9]+))?$/i;

  /** Type is a built-in constructor function (String, Function, etc.), a custom function 
   * (Primitive, SmallInt, Finite, Entries, Indexed, Key), a special value (null, undefined, NaN, 
   * Infinity), a RegExp that can both test and extract string definitions, or an enumeration 
   * (object or array) that contains subtypes as values.
   * @typedef {function|null|undefined|NaN|Primitive|SmallInt|Finite|Entries|Indexed|Key|RegExp} Type
   */

  /** Determine if a variable is of a given Type: a built-in constructor function (``String``, 
   * ``Function``, ``BigInt``, etc.), a custom constructor function (``Primitive``, ``SmallInt``, 
   * ``Finite``, ``Entries``, ``Indexed``, ``Key``), a special value (``null``, ``undefined``, ``NaN``, 
   * ``Infinity``), a RegExp that can both test and extract string definitions, or an enumeration 
   * (object or array) that contains subtypes as values.
   * ```
   * is(undefined, undefined) && is(NaN, NaN);// ⇾ true
   * is(5, Number, SmallInt, Primitive);      // ⇾ true
   * is(BigInt(5), BigInt, Finite);           // ⇾ true
   * is(Infinity, Number, Infinity);          // ⇾ true
   * is({0:'zero',1:'one'}, Indexed);         // ⇾ true
   * is([[0,'zero'],[1,'one']], Entries);     // ⇾ true
   * is(Symbol(5), Key, Symbol);              // ⇾ true
   * ```
   * @param {*} v The variable to be assessed.
   * @param {...(Type)} types One or more types or qualities to assess. If more 
   * than one is provided, the result will be true IFF the given variable possesses all of the types 
   * and qualities. If a function is provided, it is compared against the type of ``v`` which is 
   * obtained by calling ``type(v)``. If a RegExp is provided, ``v`` is tested against it.
   * @return {boolean}
   */
  const is = (v, ...types) => types.every(t => {
    switch(t){
      default:
        if(is.NaN(t)) return is.NaN(v);
        if(t && RegExp===t.constructor) return is(v, String) && t.test(v);
        if(t && Object===t.constructor) return Object.values(t).includes(v);//t is an enum
        if(v instanceof t) return true;//t is a base class
        return v===t;
      case type(v)  : return true;//String, Function, Object, null, undefined, etc...
      //case RegExp : return v && RegExp===v.constructor;
      case Primitive: return v!==Object(v);
      case SmallInt : return Number.isSafeInteger(1*v);
      case Infinity : return Infinity===v || -Infinity===v;
      case Finite   : return is.Finite(v);
      case Entries  : return is(v, Array) && v.every(entry => 2==entry.length && is(entry[0], Key));
      case Indexed  : return Array.init(v.length).every(i => v.hasOwnProperty(i));
      case Key      : return is(v, Symbol) || is(v, String) || is(v, Number);
    };//switch
  });//types.every is

  /** Determine if the given variable is NaN.
   * @param {*} v
   * @return {boolean}
   */
  is.NaN = v => 'number'==typeof v && Number(v)!==Number(v);

  /** Determine if the given variable is Infinity.
   * @param {*} v
   * @return {boolean}
   */
  is.Finite = v => 'bigint'==typeof v || Number.isFinite(v);

  /** Get the constructor function for the given variable. If you'd like type() to return 
   * something other than the Object constructor for a given type you can use type.register().
   * @param {*} v
   * @return {function} 
   */
  const type = function(v){
    assert(1==arguments.length);
    if(null==v) return v;
    // if(Object!==v.constructor) return v.constructor;
    const argConstructor = callerGlobalThis[v.constructor.name];
    if(Object!==argConstructor) return argConstructor;
    const matchRegistered = [ ..._registeredTypes ].map(t => t(v)).filter(x => x).uno;
    return matchRegistered || Object;
  };//type

  /** Registrator callback function.
   * @callback TypeRegistrator
   * @param {*} value - A variable from which to determine type.
   * @return {function|null} The constructor of the given variable, or null if unknown.
   */

  /** Register a type so that type() will identify its constructor in the future.
   * ```
   * type.register(v => MyTypes[v.toString()] || null);//register MyTypes
   * ```
   * @param {TypeRegistrator} fn
   * @return {function}
   */
  type.register = fn => _registeredTypes.add(fn);
  const _registeredTypes = new Set();

  /** Define a Serial with conversion to/from Date as needed by Google Sheets.
   * @param {*} v - If v is null or undefined, the current Date is used, 
   *     otherwise, v is used as a description to create a new Date.
   * @return {Serial}
   * 
   * @example
   * ```
   * const now = new Date();
   * const serial = new Serial(now);
   * assert(now.getTime() !== serial.value);
   * assert(now.getTime() === serial.toDate().getTime());
   * ```
   */
  const Serial = function(v){
    if(!new.target) return new Serial(v);
    if(is(v, Serial)) return v;
    const d = is(v, Date) ? v : (null==v ? new Date() : new Date(v));
    this.value = ((d.getTime()-_1stSerial.getTime())/60000-d.getTimezoneOffset())/1440;
    Object.defineProperty(this, 'valueOf', { value: function(){ return this.value } });
    this.toDate = function(){
      const intPart = Math.floor(this.value);
      const fracPart = this.value-intPart;
      const time = Math.round(fracPart*24*60*60*1000);
      const d = new Date(Date.UTC(1899, 11, 30+intPart)+time);
      d.setMinutes(d.getMinutes()+d.getTimezoneOffset());
      return d;
    };//this.toDate
  };//Serial
  const _1stSerial = new Date(Date.UTC(1899, 11, 30, 0, 0, 0, 0));
  // type.register(Serial);

  //#endregion TYPE CHECKING
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region UTILITIES

  // /** If ``obj[key]`` doesn't exist, set it to ``init`` and return it. */
  // const $ = (obj, key, init) => obj.hasOwnProperty(key) ? obj[key] : (obj[key] = init);

  /** Check if something is equivalent to another something. */
  const equivalent = (first, second) => null==first || null==second 
    ? first===second
    : false
      || first.constructor(first)===second.constructor(second)
      || true
        && Object.entries(first||[]).every(([key, val]) => equals(val, second[key]))
        && Object.entries(second||[]).every(([key, val]) => equals(val, first[key]));

  /** Create an indirect reference to eval that should be used.
   * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval
   */
  const evalIndirect = eval;//use indirect eval in strict mode for safety

  /** Use JSON.stringify() but avoid circular references and default to formatting with ``NBtab``. */
  const stringify = (value, space=nbtab) => {
    const q = [];
    return JSON.stringify(value, (_, val) => {
      if(is(val, Primitive)) return val;
      if(is(val, Function)) return val.toString();
      if(q.includes(val)) return `↺{${val && Object.keys(val)}}`;
      q.push(val);
      return val;
    }, space);//JSON.stringify
  };//stringify

  /**  */
  const minify = value => stringify(value).replace(/\n/g,'').replace(/\s+/g,' ');

  /** */
  const uno = v => {
    const arr = Object.values(v).filter(x => undefined!==x);
    assert(arr.length<=1, new Error('❌ uno: Multiple elements found!'));
    return arr[0];
  };//uno

  /** Filter out all 'empty' elements. */
  const nonempty = v => v.filter(_ => true);

  /** */
  const transpose = v => nonempty(v)[0].map((_, i) => v.map(arr => arr[i]));

  /** */
  const toCamelCase = str => str.toLowerCase()
    .replace(/[^a-zA-Z0-9 ]/g, '').trim()
    .replace(/(?:^\w|[A-Z]|\b\w)/g, (word, i) => 
      i ? word.toUpperCase() : word.toLowerCase()
    ).replace(/\s+/g, '');//toCamelCase

  /** */
  const clone = v => is(v, Primitive) 
    ? Primitive(v) 
    : Object.defineProperties(
      is(v, Function) 
        ? (...args) => v.apply(v, args) 
        : (is(v, Array) ? [] : {}), 
      Object.getOwnPropertyDescriptors(v)
    );//defineProperties

  /** */
  const escapeRegex = str => str.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');

  /** Create an enum from the given values.
   * @param {*[]} values
   * @return {object}
   */
  const ENUM = (...enumerations) => {
    const e = enumerations.flat();
    const obj = e && e.constructor===Array ? e.reduce((a, key) => Object.assign(a, { [key]: key }), {}) : e;
    const validatorDesc = { validate: { value: v => Object.values(obj).includes(v) } };
    const desc = Object.fromEntries(Entries(obj).map(([key, value]) => [ key, { enumerate: true, value } ]));
    return Object.defineProperties(obj, Object.assign(desc, validatorDesc));
  };//ENUM

  /** Encode a value in a given `from_base` to a new `to_base`.
   */
  const encode = (value, from_base=10, to_base=87) => {
    var rangeChars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^*-_=+,.?/\|:;()[]{}❤♻⚜⚠©®™⚙⎈★☇☈☉☊☋☌☍☏☐☒☖☗☙☚☛☜☞☟☡☤☥☧☨☩☫☬☭☰☱☲☳☴☵☶☷☻☼☽☾☿♁♃♄♅♆♇♔♕♖♗♘♙♚♛♜♝♞♡♢♤♧♩♪♫♬♭♮♯♰♱♲♳♴♵♶♷♸♹♺♼♽⚀⚁⚂⚃⚄⚅⚐⚑⚘⚚⚝⚞⚟⚢⚣⚤⚥⚦⚨⚩⚬⚭⚮⚯⚲⚳⚴⚵⚶⚷⚸⚹⚺⚻⚼⚿⛀⛁⛂⛃⛆⛇⛉⛊⛋⛌⛍⛐⛒⛕⛖⛗⛘⛙⛚⛛⛜⛝⛞⛟⛠⛡⛢⛣⛤⛥⛦⛧⛨⛫⛬⛭⛮⛯⛶⛻⛼⛾⛿✀✁✃✄✎✐✑❥❦❧';
    var range = rangeChars.split('');
    //console.log(range[range.length-1]);
    // if(!from_base) from_base = 10;
    // if(!to_base) to_base = 87;
    if(range.length <= to_base) to_base = range.length-1;
    var from_range = range.slice(0, from_base);
    var to_range = range.slice(0, to_base);
    var dec_value = (''+value).split('')
    .reverse().reduce(function (carry, digit, i){
      if(from_range.indexOf(digit)<0) throw new Error(
        'Invalid digit `'+digit+'` for base '+from_base+'.'
      );//error
      return carry += from_range.indexOf(digit) * (Math.pow(from_base, i));
    }, 0);//reduce
    var new_value = '';
    while(0<dec_value){
      new_value = to_range[dec_value % to_base] + new_value;
      dec_value = (dec_value - (dec_value % to_base)) / to_base;
    }//while
    if(new_value.includes('NaN')) console.error(
      `NaN detected: encode(${value}, ${from_base}, ${to_base}) → ${new_value}`
    );//console.error
    return new_value || '0';
  }//encode
  // encode.max4 = 57*24*60*60*1000;//57 days
  encode.max4 = 15*60*60*1000;//15 hours

  /** Throw the given error.
   * @param {Error|*} exception
   */
  const error = exception => { throw exception };

  /** Validate that a given condition is true. Always passes when Settings.Release is true.
   * ```
   * assert(myArray.length, 'Array is empty!');//returns myArray.length
   * ```
   * @param {*} [test] Anything that can be tested for true/false, including nothing at all.
   * @param {Error|*} [exception] Exception to throw on failure. If a string, a generic Error will be used.
   * @return {*} The first parameter 'test' is always returned.
   */
  function assert(test, exception=new Error('❌ assert failed')){
    //define with the 'function' keyword instead of 'const' so that it gets hoisted
    return test || Settings.Release ? test : error(exception);
  };//assert

  /** Only execute in debug mode. */
  const debug = func => Settings.Debug && func();

  /** Block further execution for some time. Works on server and client. */
  const sleep = millis => {
    log(`Sleeping for ${millis}ms`);
    return Utilities && 'function'==typeof Utilities.sleep
      ? Utilities.sleep(millis)
      : new Promise(resolve => setTimeout(resolve, millis));
  };//sleep

  /** Get the Duration between two DateTimes.
   * 
   * ```
   * Duration().as('ms');//Milliseconds from entrypoint.began to now. E.g: 5000
   * Duration().as('ms');//Milliseconds from last call to now. E.g: 1
   * Duration({ name: 'profiler' });//Milliseconds from entrypoint.began to now. E.g: 5002
   * ```
   * @param {DateTime} [start] Defaults to the last time Duration was called with the given name, 
   * or entrypoint.began.
   * @param {DateTime} [end] Defaults to now.
   * @return {Duration}
   */
  const Duration = ({ start, end, name='' }={}) => {
    const now = DateTime.now();
    start = start || _durationLastCall[name] || now;
    end = end || now;
    if(end < start) [ start, end ] = [ end, start ];
    assert(is(start, DateTime) && is(end, DateTime));
    _durationLastCall[name] = now;
    return Interval.fromDateTimes(start, end).toDuration();
  }//Duration
  const _durationLastCall = {};

  /** Make a partial call to a function so that it can be called with more parameters later.
   * @param {function} func The function to build the partial wrapper for.
   * @param {...*} args Array of arguments to be pre-loaded into the partial function call, defaults to [].
   * @return {function} Whatever the given func returns.
   * @example
   * ```
   * const partialLog = partial(log, 'one', 'two');
   * partialLog('three', 'four');//console log: "one two three four"
   * ```
   */
  const partial = (func, ...args) => (...moreArgs) => func.apply(func, [ ...args, ...moreArgs ]);

  /** Utility to make logging messages easier.
   * @param {string} type
   * @param {...*} [messages]
   * @return {*} The first message.
   */
  const _log = (type, ...args) => {
    const firstArg = args[0];
    if(_log_to_sheet && _log_to_sheet.getRange) retryGoogle(() => _log_to_sheet
      .getRange(_log_to_row++, 1, 1, 2+args.length+2)
      .setValues([[
        new Serial().value, type, _log_pre.trim(), ...args, _log_post.trim() 
      ]])//setValues
    );//retryGoogle
    console[type].apply(null, [
      ...null==_log_pre  ? [] : [ _log_pre  ], 
      ...args,
      ...null==_log_post ? [] : [ _log_post ], 
    ]);//apply
    return firstArg;
  };//_log

  const log   = partial(_log, 'log'    );
  log.info    = partial(_log, 'info'   );
  log.warn    = partial(_log, 'warn'   );
  log.error   = partial(_log, 'error'  );
  log.time    = partial(_log, 'time'   );
  log.timeEnd = partial(_log, 'timeEnd');

  let _log_pre, _log_post, _log_to_sheet, _log_to_row = 1;
  log.configure = ({ pre='', post='', sheet, shouldClearSheet=false }={}) => {
    _log_pre=pre, _log_post=post, _log_to_sheet=sheet;
    if(!sheet || !sheet.getRange) return;
    const frozenRow = retryGoogle(() => sheet.getFrozenRows());
    const lastRow = retryGoogle(() => sheet.getLastRow());
    if(shouldClearSheet) sheet.getRange(
      `${1+frozenRow}:${(lastRow||1)-(frozenRow||1)+1}`
    ).clearContent();
    _log_to_row = 1+Math.max(frozenRow, shouldClearSheet ? frozenRow||1 : lastRow||1);
  };//log.configure

  /** Retry a given function a number of times and if it always fails, try something else instead.
   * @param {function} onTry Function to try.
   * @param {*} [options]
   * @param {number} [options.attemps=1] Number of tries to attempt.
   * @param {number} [options.escalation=1] Growth factor for increasing the wait time on each attempt.
   * @param {number} [options.milliseconds=1000] Milliseconds to wait between attempts.
   * @param {function} [options.onFail=Error] What to do if all attempts fail.
   * @return {*} Result of the given function or options.onFail.
   */
  const retry = (onTry, { attempts=1, escalation=0, milliseconds=100 }={}) => {
    let escalate = 1;
    while(0<attempts--){
      try{ return 'function'==typeof onTry ? onTry() : onTry }
      catch(err){
        if(0<attempts) sleep(escalate*milliseconds);
        else return err;//out of attempts so return the error in case the caller wants to throw it
        escalate += escalation;
      }//catch err
    }//while
  };//retry

  /** */
  const retryGoogle = (onTry, options) => {
    const result = retry(onTry, { ...options, escalation: 1, attempts: 4 });
    assert(!is(result, Error), result);
    return result;
  };//retryGoogle

  /** Time a function to see how long it takes in the logs.
   * @param {function} func Function to profile.
   * @param {object} [options]
   * @param {string} [options.desc] Description to include in log. Defaults to the function name, file,
   *        and line number retrieved from getCallstack(): `${mr.func} (${mr.file}:${mr.line})`.
   * @param {boolean} [options.shouldLog] Defaults true to use console log to output the duration.
   * @param {*} [thisArg] Context to run the given function with. Uses func.call(thisArg).
   * @return {*} Result of the given function. A ``Duration`` is also provided via an ``out_duration``
   *        property injected into the provided ``options`` argument.
   */
  const profile = function(func, { desc, shouldLog=true, out_duration, thisArg } = {}){
    if(!desc){
      const stack = getCallstack()[1];
      desc = stack.func + ' (' + stack.file + ':' + stack.line + ')';
    }//if
    _profileStack.push(desc);
    const stackDesc = _profileStack.reduce((a,x,i)=>a+' » '+x,'');
    const start = DateTime.now();
    const result = func.call(thisArg);
    _profileStack.pop();
    const duration = (arguments[1]||{}).out_duration = Duration({ start });
    if(shouldLog) log('⏱ PROFILE: ' + duration.as('ms') + 'ms to complete' + stackDesc);
    return result;
  }//profile
  const _profileStack = [];

  /** Callback for loop that maps each element in a collection (array or object).
   * @typedef {function} MapLooper
   * @param {*} val
   * @param {number|string|Symbol} key
   * @param {*[]} arr
   * @return {*}
   */
  /** Callback for loop that reduces elements in a collection (array or object).
   * @typedef {function} ReduceLooper
   * @param {*} accum
   * @param {*} val
   * @param {number|string|Symbol} key
   * @param {*[]} arr
   * @return {*}
   */
  /** IMMUTABLE. Loop can filter, map, reduce, and forEach through all the elements of a 
   * collection (array or object) and supports the use of three new keywords:
   * - ``loop.CONTINUE`` will filter the element from the mapped result.
   * - ``loop.BREAK`` will end the loop early.
   * - ``loop.EMPTY`` will map the element as ``empty`` for arrays.
   * @param {ReduceLooper|MapLooper} looper Function that gets called on each element whose return 
   *        value contributes to the result.
   * @param {*} [initial] If undefined, ``looper`` will be called  as a mapper, otherwise it will 
   *        be called as a reducer that takes an extra ``accum`` parameter in the first position.
   * @return {*}
   * @example
   * ```
   * loop([ 1,2,3,4 ], x => x%2 ? x : loop.CONTINUE); // ⇾ [ 1,3 ]
   * loop([ 1,2,3,4 ], x => x%2 ? x : loop.BREAK);    // ⇾ [ 1 ]
   * loop([ 1,2,3,4 ], x => x%2 ? x : loop.EMPTY);    // ⇾ [ 1,,3, ]
   * ```
   */
  const loop = (obj, looper, { back, initial } = {}) => {
    const isReduce = !is(initial, undefined);
    const arr = Object.entries(obj);
    let i, accum = isReduce ? initial : [];
    LOOP: for(i = (back ? arr.length-1 : 0); back ? 0<=i : i<arr.length; back ? --i : ++i){
      const [ key, val ] = arr[i];
      const args = isReduce ? [ accum, val, key, arr ] : [ val, key, arr ];
      try{
        if(isReduce) accum = looper.apply(null, args);
        else accum.push([ key, looper.apply(null, args) ]);
      }catch(err){
        if(err===_BREAK) break;
        if(err===_CONTINUE) continue LOOP;
        accum.pushEmpty();
        if(err===_EMPTY) continue LOOP;
        throw err;
      }//catch err
    }//for i
    if(isReduce) return accum;
    if(is(obj, Array)) return accum.map(([_, val]) => val);
    return Object.fromEntries(nonempty(accum));
  };//loop
  const _CONTINUE = {}, _BREAK = {}, _EMPTY = {};
  Object.defineProperties(loop, {
    CONTINUE: { get: () => { throw _CONTINUE } },
    BREAK   : { get: () => { throw _BREAK    } },
    EMPTY   : { get: () => { throw _EMPTY    } },
  });//defineProperties exports

  /** Capture the current callstack and parse it for easy access to line number, file name, etc.
   * @return {[string]}
   */
  const getCallstack = () => {
    try { throw new Error('🦎') }
    catch (err) {
      const display = err.stack.replace(/^.*🦎\n/, '')
      .replace(/\n\s+at __GS_INTERNAL_top_function_call__.gs:1:8/, '');
      let matches = display.split(/\s*at /g);
      matches.shift();//first element is blank
      matches.shift();//next element is this getCallStack
      matches = matches.map(x => ({
        //e.g: "test (mr:1824:3)"
          func: x.includes('(') ? x.match(/\S+/).pop() : '(anonymous)',
          file: x.includes('(') ? x.match(/\((.+?)[:)]/).pop() : x.match(/[^:]+/).pop(),
          line: x.match(/:(\d+):/).pop()*1,
        column: x.match(/:(\d+)(?:\)|$)/).pop()*1,
      }));//map
      matches.display = display;
      return matches;
    }//catch
  };//getCallstack

  /**
   * Get some lorem ipsum placeholder text.
   * 
   * @param {string} url
   * URL to get the lorem ipsum from, defaults to 'https://loripsum.net/api/'.
   * 
   * @param {string[]} [options]
   * Options to provide to the given url, defaults to [1,'short','plaintext'].
   * 
   * @return {string}
   */
  const getLoremIpsum = (url='https://loripsum.net/api/', ...options) => UrlFetchApp.fetch(
    (options.length ? options : [ 1, 'short', 'plaintext' ])
    .reduce((url, option) => url += option + '/', url)
  ).getContentText();

  /** Convert a character to its ASCII numerical code. */
  const atoi = letter => letter.charCodeAt(0);

  /** Convert a ASCII numerical code to its character. */
  const itoa = ascii => String.fromCharCode(ascii);

  /** Convert a column number to its letter address. */
  const colNumToLet = n => 
    (assert(0<n) && n<=26 ? '' : itoa(asciiA+(n-1-26)/26)) + itoa(asciiA+(n-1)%26);

  /** Convert a table (2D array) of data into an array of objects where the 
   * column headings are converted to object keys.
   */
  const tableToObjects = (table, { replacer=null, trimEmpty=true }={}) =>
    table.map((row, r) =>
      row.reduce((rowObj, _, c) => {
        const heading = table[0][c].valueOf();
        const replaced = r && 'function' == typeof replacer
          ? replacer(r, heading, table[r][c])
          : table[r][c];
        if(!replaced && 0!==replaced) return rowObj;
        return { ...rowObj, [heading]: replaced };
      }, {})//reduce rowObj
    ).slice(1)

  /** Returns true IFF we have used up at least 80% of our runtime quota.
   * @param {number} [estimated] Estimated 
   */
  const isTimeUp = (estimated=_entryType.GASQuotaRuntime*0.2) => 
    _entryType.GASQuotaRuntime < Math.max(1000, 1.2*estimated)+Duration({ start: now }).as('ms');

  //#endregion UTILITIES
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region PROTOTYPES
  // //#region Set
  // Set.prototype._forEach = Set.prototype.forEach;//keep a ref to the original in case we need it
  // delete Set.prototype.forEach;//make room for using the Object.forEach for consistency
  // //#endregion Set
  // //#region Object
  // /** Define new properties on this object.
  //  * @param {descriptor[]} descriptors - Many descriptors can be provided to create a merged result.
  //  * @param {*} [descriptor.value]
  //  * @param {function} [descriptor.get]
  //  * @param {function} [descriptor.set]
  //  * @param {boolean} [descriptor.writable]
  //  * @param {boolean} [descriptor.enumerable]
  //  * @param {boolean} [descriptor.configurable]
  //  * @param {string[]} [descriptor.keys] - Other keys to serve as aliases to the same property.
  //  * @return {object}
  //  */
  // if(Object.prototype.define) console.warn('❌ Overriding existing property: Object.define');
  // Object.defineProperties(Object.prototype, {
  //   define: { value: function(descriptors = {}){
  //     const descCombined = Object.getOwnPropertyNames(descriptors).reduce((descCombined, key) => {
  //       const aliases = [ ...new Set([ key, ...(descriptors[key].keys||[]) ]) ];
  //       aliases.forEach(alias => descCombined[alias] = descriptors[key]);
  //       return descCombined;
  //     }, {});//reduce desc
  //     const thisKeys = Object.getOwnPropertyNames(this);
  //     Object.getOwnPropertyNames(descCombined).every(key => 0
  //       || descCombined[key].configurable 
  //       || !thisKeys.includes(key)
  //       || console.warn('❌ Overriding existing property: '+key)
  //     ) || console.warn('❌ Object.define: properties overridden!');
  //     return Object.defineProperties(this, descCombined);
  //   }},//define
  // });//defineProperty define

  // Object.prototype.define({

  //   /**
  //    * Get all the property descriptors of this object.
  //    *
  //    * @return {object}
  //    */
  //   properties: { value: function(){ return Object.getOwnPropertyDescriptors(this) } },
    
  //   /** Assign properties from other objects to this one. */
  //   assign: { value: function(...sources){ return Object.assign(this, ...sources) } },

  //   /** Freeze this object from future changes. */
  //   freeze: { value: function(){ return Object.freeze(this) } },

  //   /** Check if this is equivalent to the provided value. */
  //   equals: { value: function(target){
  //     if(is(this, Primitive)) return Primitive(this)===Primitive(target);
  //     return Object.entries(this).every(([key, val]) => val.equals(target[key]) );
  //   }},//equals

  //   /**
  //    * Create new getters on this object that memoizes expensive calculations. The new 
  //    * getters are function objects with added properties to give access to the cached
  //    * calculation result. When the function is invoked directly, the expensive calculation 
  //    * can be re-run and re-cached. If no getters are provided, memoized getters will be
  //    * created for every function on this object that begins with 'get', has length zero,
  //    * and is configurable, where the new properties drop the 'get' prefix. For example, 
  //    * '.getId()' becomes '.id'.
  //    *
  //    * @param {getter[]} [getters]
  //    * 
  //    * @param {string[]} [getter.keys]
  //    * 
  //    * @param {function} [getter.func]
  //    * 
  //    * @param {boolean} [getter.enumerable]
  //    * 
  //    * @param {string|boolean} [getter.regetter]
  //    * Name of the regetter to create; or true to make the getter.keys into regetter 
  //    * functions themselves; otherwise no regetter is made
  //    * 
  //    * @return {*}
  //    * 
  //    * @example
  //    *    let ctr = 5;
  //    *    let obj = {}.memoize([ { keys: [ 'ctr', 'counter' ], func: () => ctr++ }, ]);
  //    *    obj.ctr;       //=>5 (func is run and cached)
  //    *    obj.counter;   //=>5 (cached result retrieved)
  //    *    obj.ctr();     //=>6 (func is run and cached)
  //    *    obj.counter(); //=>7 (func is run and cached)
  //    * 
  //    * @example
  //    *    let ctr = 5;
  //    *    let obj = { getCtr: () => ctr++ }.memoize();
  //    *    obj.ctr;   //=> 5 (getCtr is run and cached)
  //    *    obj.ctr;   //=> 5 (cached result retrieved)
  //    *    obj.ctr(); //=> 6 (getCtr is run and cached)
  //    *    obj.ctr;   //=> 6 (cached result retrieved)
  //    */
  //   memoize: { value: function(getters = []){
  //     const configurable = true;
  //     const props = this.props;
  //     const _getters = getters.length ? getters : props.reduce((_getters, desc, key) => 
  //       desc.configurable && key.startsWith('get') && is(desc.value, Function) && 0===desc.value.length 
  //         ? [ ..._getters, {
  //           keys: [ key[3].toLowerCase()+key.substring(4) ], 
  //           func: desc.value, 
  //           regetter: key, 
  //           enumerable: desc.enum,
  //         } ] : _getters, 
  //     []);//reduce getters
  //     const desc = _getters.reduce((desc, getter) => {
  //       const keys = getter.keys;
  //       const enumerable = is(getter.enumerable, Boolean) ? getter.enumerable : true;//default to true
  //       const getterWrapper = function(){
  //         // const got = profile(
  //         //   () => getter.func.apply(this, arguments), 
  //         //   `memoize: ${is(getter.regetter, String) 
  //         //     ? getter.regetter 
  //         //     : keys[0]}: ${getter.func.name}()`
  //         // );//profile
  //         const got = getter.func.apply(this, arguments);
  //         const result = true===getter.regetter ? getterWrapper.assign(got) : got;
  //         this.define({ [keys[0]]: { enumerable, configurable, value: result, keys }});
  //         return result;
  //       };//getterWrapper
  //       if(!desc[keys[0]]) desc[keys[0]] = { enumerable, configurable, get: getterWrapper, keys };
  //       else if(Settings.warnMemoizeRedefine) log.warn('Skipping re-definition of property: '+keys[0]);
  //       if(is(getter.regetter, String)) desc[getter.regetter] = { enumerable, configurable, value: getterWrapper };
  //       return desc;
  //     }, {});//desc
  //     // console.log('memoize: desc: '+JSON.stringify(desc, (k,v) => is(v, Function) ? v.name : v));
  //     return this.define(desc);
  //   }},//memoize

  //   /** Make a deep clone of this object. */
  //   clone: { value: function(){ return is(this, Primitive) ? Primitive(this) : Object.defineProperties(
  //     is(this, Function) ? (...args) => this.apply(this, args) : (is(this, Array) ? [] : {}),this.properties()
  //   )}},//clone

  //   isIndexed: { value: function(){ return is(this, Indexed) } },

  //   /** IMMUTABLE. Get this object as an array. */
  //   asArray: { value: function(){
  //     if(is(this, Array)) return this;
  //     if(is(this, Set)) return [ ...this ];
  //     const iterate = this.next ? () => this.hasNext() && this.next() : this.nextNode;
  //     if(!is(iterate, Function)) return Object.defineProperties([], this.properties());
  //     let current, result = [], maxDepth = 2^16;//65536
  //     while(current = iterate() && --maxDepth) result.push(current);
  //     assert(maxDepth);
  //     return result;
  //   }},//asArray

  //   /** Callback for loop that maps each element in a collection (array or object).
  //    * @typedef {function} MapLooper
  //    * @param {*} val
  //    * @param {number|string|Symbol} key
  //    * @param {*[]} arr
  //    * @return {*}
  //    */

  //   /** Callback for loop that reduces elements in a collection (array or object).
  //    * @typedef {function} ReduceLooper
  //    * @param {*} accum
  //    * @param {*} val
  //    * @param {number|string|Symbol} key
  //    * @param {*[]} arr
  //    * @return {*}
  //    */

  //   /** IMMUTABLE. Loop can filter, map, reduce, and forEach through all the elements of a 
  //    * collection (array or object) and supports the use of three new keywords:
  //    * - ``CONTINUE`` will filter the element from the mapped result.
  //    * - ``BREAK`` will end the loop early.
  //    * - ``EMPTY`` will map the element as ``empty`` for arrays.
  //    * ```
  //    * [ 1,2,3,4 ].loop(x => x%2 ? x : CONTINUE); // ⇾ [ 1,3 ]
  //    * [ 1,2,3,4 ].loop(x => x%2 ? x : BREAK);    // ⇾ [ 1 ]
  //    * [ 1,2,3,4 ].loop(x => x%2 ? x : EMPTY);    // ⇾ [ 1,,3, ]
  //    * ```
  //    * @param {ReduceLooper|MapLooper} looper Function that gets called on each element whose return 
  //    * value contributes to the result.
  //    * 
  //    * @param {*} [initial] If undefined, ``looper`` will be called  as a mapper, otherwise it will 
  //    * be called as a reducer that takes an extra ``accum`` parameter in the first position.
  //    */
  //   loop: { value: function(looper, initial){ return loop(this, looper, { initial }) } },
  //   loopBack: { value: function(looper, initial){ return loop(this, looper, { back: true, initial }) } },
    
  //   //iterate over any object's enumerable properties
  //   //this does NOT overwrite Array.prototype.forEach or Set.prototype.forEach
  //   forEach: { value: function(fn, thisArg){
  //     Object.entries(this).forEach(([key, value]) => fn(value, key, this), thisArg);
  //   }},//forEach

  //   //iterate over any object's enumerable properties
  //   map: { value: function(fn, thisArg){
  //     return Object.fromEntries(Object.entries(this).map(([key, value]) => [ key, fn(value, key, this) ], thisArg));
  //   }},//map

  //   //iterate over any object's enumerable properties
  //   filter: { value: function(fn, thisArg){
  //     return Object.fromEntries(Object.entries(this).filter(([key, value]) => fn(value, key, this), thisArg));
  //   }},//filter

  //   //iterate over any object's enumerable properties
  //   filterIndex: { value: function(fn, thisArg){
  //     return Object.entries(this).filter(([key, value]) => fn(value, key), thisArg).map(([i]) => i);
  //   }},//filterIndex

  //   //iterate over any object's enumerable properties
  //   reduce: { value: function(fn, initial, thisArg){
  //     return Object.entries(this).reduce((reduced, [key, value]) => fn(reduced, value, key, this), initial, thisArg);
  //   }},//reduce

  //   //iterate over any object's enumerable properties
  //   every: { value: function(fn, thisArg){
  //     return Object.entries(this).every(([key, value]) => fn(value, key, this), thisArg);
  //   }},//every

  //   //iterate over any object's enumerable properties
  //   some: { value: function(fn, thisArg){
  //     return Object.entries(this).some(([key, value]) => fn(value, key, this), thisArg);
  //   }},//some

  //   /** Splitter callback function.
  //    * @callback Splitter
  //    * @param {*} value - An element from this object.
  //    * @param {number|string} key - The original key for the given element.
  //    * @param {object|array} original - This object.
  //    * @return {number|string} The key of the new object where the value should belong to.
  //    */

  //   /** Split the properties of this object into multiple objects. Returns a new object that contains one 
  //    * or more other objects containing the split properties. The provided splitter callback determines 
  //    * the key for which subset each property should be sent to.
  //    * ```
  //    * { one:1, two:2, three:3, four:4 }.split(x => x % 2) //⇾ { { two:2, four:4 }, { one:1, three:3 } }
  //    * [ 1, 2, 3, 4, 5, 6 ].split(x => x % 2) //⇾ [ [ 2, 4, 6 ], [ 1, 3, 5 ] ]
  //    * ```
  //    * @param {Splitter} fn - A callback function that directs each element to one of the split objects.
  //    * @return {object|array}
  //    */
  //   split: { value: function(fn){ return this.reduce((split, v, i) => {
  //     const key = fn(v, i, this);
  //     if(!split.hasOwnProperty(key)) split[key] = this.constructor();
  //     split[key][is(this, Array) ? split[key].length : i] = v;
  //     return split;
  //   }, this.constructor())}},//split

  //   nonnull: { get: function(){ return this.filter(x => null!==x) } },

  //   includes: { value: function(value){ return this.values().filter(v => v===value) } },

  //   lastKey: { get: function(){
  //     if(this.isIndexed()) return this.length-1;
  //     const keys = Object.keys(this);
  //     return keys[keys.length-1];
  //   }},//lastKey

  //   last: { get: function(){ return this[this.lastKey] } },

  //   push: { value: function(value){
  //     assert(this.isIndexed(), new TypeError('Cannot push() on a non-array-indexed object.'));
  //     Object.assign(this, { [this.length]: value });
  //     return ++this.length;
  //   }},//push

  //   unshift: { value: function(value){
  //     assert(this.isIndexed(), new TypeError('Cannot unshift() on a non-array-indexed object.'));
  //     Object.fromEntries(Object.entries(this).map(([key, val]) => [ key+1, val ]).unshift([ 0, value ]));
  //     return ++this.length;
  //   }},//unshift

  //   pop: { value: function(){
  //     const i = this.isIndexed() ? this.length-1 : Object.keys(this).last;
  //     const popped = this[i];
  //     delete this[i];
  //     return popped;
  //   }},//pop

  //   shift: { value: function(){
  //     const i = this.isIndexed() ? 0 : Object.keys(this)[0];
  //     const shifted = this[i];
  //     delete this[i];
  //     return shifted;
  //   }},//shift

  //   //unique: make user use filter instead? e.g: arr.filter((x,i,arr) => i===arr.indexOf(x))

  // });//Object.prototype.define
  // //#endregion Object
  // //#region String
  // String.prototype.define({

  //   // toCamelCase: { value: function(){
  //   //   return this.toLowerCase()
  //   //   .replace(/[^a-zA-Z0-9 ]/g, '').trim()
  //   //   .replace(/(?:^\w|[A-Z]|\b\w)/g, (word, i) => 
  //   //     i ? word.toUpperCase() : word.toLowerCase()
  //   //   ).replace(/\s+/g, '');
  //   // }},//toCamelCase
  //   toCamelCase: { value: function(){ return toCamelCase(this) } },

  //   count: { value: function(str){ 
  //     return (this.length - this.replace(new RegExp(escapeRegex(str), 'g'), '').length) / str.length;
  //   }},//count

  //   isInt: { value: function(){ return Number.isInteger(Number(this)) && 0 <= Number(this) } },

  //   minify: { value: function(){ return minify(this) } },

  // });//String.prototype.define
  // //#endregion String
  // //#region Array
  // Array.define({ init: { value: (length, filler=i=>i) => Array(length).fill(0).map((_, i) => filler(i))}});
  // Array.prototype.define({

  //   /** */
  //   uno: { get: function(){ return uno(this) } },

  //   /** Filter out the empties. */
  //   nonempty: { value: function(){ return this.filter(_ => true) } },

  //   /** Calculate the average of this array. */
  //   average: { value: function(){ return this.reduce((a, b) => a + b) / this.length; } },

  //   /** Get a transpose of this 2D array. */
  //   transpose: { value: function(){ return this.nonempty()[0].map((_, i) => this.map(arr => arr[i])) } },

  //   /** Determine if Object.fromEntries() may be used on this array. */
  //   isEntries: { value: function(){ return is(this, Entries) } },

  //   /** Convert this array into an object with the same keys and values. */
  //   asObject: { value: function(){ return Object.defineProperties({}, this.properties()) } },

  //   /** Determine if the element at the given index is empty (distinct from undefined or null). */
  //   hasEmpty: { value: function(i){ return 0<=i ? !this.some((_, j) => i==j) : Object.values(this).length==this.length } },

  //   /** MUTABLE! Append some empty values to the end of this array. */
  //   pushEmpty: { value: function(n = 1){ return this.length+=n } },

  //   /** MUTABLE! Prepend some empty values to the front of this array. */
  //   unshiftEmpty: { value: function(n = 1){
  //     this.reverse();
  //     this.pushEmpty(n);
  //     this.reverse();
  //     return this.length;
  //   }},//unshiftEmpty

  // });//Array.prototype.define
  // //#endregion Array
  // //#region Function
  // Function.prototype.define({

  //   partial: { value: Object.assign(function(...args){
  //     //return !args.length ? this : (...remainingArgs) => this.apply(this, [ ...args, ...remainingArgs ]);
  //     return (...remainingArgs) => {
  //       this.apply(this, remainingArgs.map((arg, i) => 
  //         arg===Function.prototype.partial.skip ? args[i] : arg
  //       ));//apply
  //     };//return
  //   }, { skip: {} })},//partial

  // });//Function.prototype.define
  // //#endregion Function
  // //#region Number
  // Number.prototype.define({

  //   pad: { value: function(len){ return '0'.repeat(len - this.toString().length) + this.toString() } },

  //   currency: { value: function(places = -1, sym = '$'){
  //     const rounded = Math.round(Number(this)*100)/100;
  //     if(places<0) places = 1*(rounded % 1).toFixed(2) ? 2 : 0;
  //     return sym + rounded.toFixed(places);
  //   }},//currency

  // });//Number.prototype.define
  // //#endregion Number
  //#endregion PROTOTYPES
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region DEPENDENCIES (GAS, luxon)

  const {
    DateTime, /*Duration,*/ Interval, //luxon stuff (valid on both server and client)
    HtmlService, Property, Cache, Lock, Trigger, UI, //GAS stuff (will be undefined on client)
  } = (() => _isClient ? luxon : luxonInit({
    HtmlService: callerGlobalThis.HtmlService,
    Property: Object.defineProperties({}, {
      file  : { get: () => retryGoogle(() => PropertiesService.getDocumentProperties()), enumerable: true },
      script: { get: () => retryGoogle(() => PropertiesService.getScriptProperties  ()), enumerable: true },
      user  : { get: () => retryGoogle(() => PropertiesService.getUserProperties    ()), enumerable: true },
    }),//Property
    Cache: Object.defineProperties({}, {
      file  : { get: () => retryGoogle(() => CacheService.getDocumentCache()), enumerable: true },
      script: { get: () => retryGoogle(() => CacheService.getScriptCache  ()), enumerable: true },
      user  : { get: () => retryGoogle(() => CacheService.getUserCache    ()), enumerable: true },
    }),//Cache
    Lock: Object.defineProperties({}, ['Document', 'Script', 'User'].reduce((lock, name) => 
      Object.assign(lock, { [name]: {
        // enumerable: false,//must remain false or else we will inadvertently access these getters
        get: () => {
          // log(`Lock.${name} getter invoked!`);
          const beginTryLock = new Date();
          const service = retryGoogle(() => LockService[`get${name}Lock`]());
          return !service ? null : Object.assign(service, {
            criticalSection: func => {
              for(let ready=false; !ready;){
                assert(!isTimeUp());
                if(isTimeUp()){
                  retryGoogle(() => service.releaseLock());//just in case
                  log.error(`Times up for Lock.${name} after ${Duration({beginTryLock}).as('ms')}ms`);
                  return TIMESUP;
                }//if isTimeUp()
                ready = retryGoogle(() => service.tryLock(secToMs(10)));//tryLock returns boolean
              }//for ready
              assert(retryGoogle(() => service.hasLock()));
              log(`Lock.${name} obtained in ${Duration({beginTryLock}).as('ms')}ms`);
              const beginHasLock = new Date();
              const result = retry(() => func());//result may be an error
              retryGoogle(() => service.releaseLock());
              log(`Lock.${name} was retained for ${Duration({beginHasLock}).as('ms')}ms`);
              //now that we've released the lock we can throw the error if there was one
              return is(result, Error) ? error(result) : result;
            },//criticalSection
          });//Object.assign
        },//get
      }}), {} //Object.assign
    )),//Lock
    Trigger: Object.defineProperties({}, {
      project: { get: () => retryGoogle(() => ScriptApp.getProjectTriggers ()), },
      script : { get: () => retryGoogle(() => ScriptApp.getScriptTriggers  ()), },
      //user : { get: () => retryGoogle(() => ScriptApp.getUserTriggers(FORM)), },
    }),//Trigger
    UI: retry(() => Object.keys(globalThis).map(key => 
      'App'!=key.slice(-3) || !is(globalThis[key].getUi, Function) ? 0 
        : retryGoogle(() => globalThis[key].getUi())
    ).filter(x => 0!==x).uno),//UI
  }))();//do all this in a function so we can yield const variables

  //🔥 roll our own file-based property service that reads / writes to the document

  //handy alias for creating a critical section with the Document lock service
  // const CS = Lock.Document.criticalSection;

  //#endregion DEPENDENCIES
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region ENTRYTYPE

  /** */
  const EntryType = {
    client        : {                               name: '🌈' },
    webappBackend : { GASQuotaRuntime: minToMs(30), name: '⛅' },
    webappFrontend: { GASQuotaRuntime: minToMs(30), name: '💧'  },
    macro         : { GASQuotaRuntime: minToMs( 6), name: '🌞' },
    trigger       : { GASQuotaRuntime: minToMs( 6), name: '⚡' },
  };//EntryTypes

  /** Where you can describe app entry and other state. */
  const setEntryType = type => (assert(EntryType.client!==type || _isClient), _entryType = type);
  const now = DateTime.now();
  let _entryType;

  //#endregion ENTRYTYPE
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region METADATA
  const License = 'mr.js ™© '+now.year+' Michael Wilford. All Rights Reserved.';
  const Version = '0.1.0';
  //#endregion METADATA
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region DRIVE

  /** Get the url for the script with the given id. */
  //use 'function' instead of 'const' for hoisting
  function getScriptUrl(id){ return `https://script.google.com/macros/s/${id}/exec?scriptid=${id}`; }

  /** Register to get notified whenever a given property is changed. */
  const _notifyOnPropChange = [];
  const notifyOnPropChange = {
    //e.g: { name: 'Tab', notifier: function, old: true, new: false, notified: 1663092258356 }
    /** */
    create: notification => {
      assert(notification.name && notification.notifier);
      if(_notifyOnPropChange.some(existingNotification => existingNotification.name==notification.name)) return;
      _notifyOnPropChange.push(notification);
    },//create
    /** Trigger a notification  */
    notify: (name, change) => {
      const now = DateTime.now().valueOf();//in milliseconds (number)
      const notifications = !name ? _notifyOnPropChange : _notifyOnPropChange
      .filter(notification => name==notification.name && !notification.notified);
      notifications.forEach(notification => {
        if(notification.old.equals(change)) return;//not actually a change
        notification.new = change;
        notification.notified = now;
        notification.notifier(notification);
        notification.old = change;
      });//forEach notification
    },//notify
  };//notifyOnPropChange

  // /** Read and write to each of the various PropertyServices.
  //  * @param {string} [name] Name of the property to read/write (null: delete all; undefined: get all).
  //  * @param {string} [value] Value to write (null: delete specified; undefined: get specified).
  //  * @return {string|undefined}
  //  * @example
  //  * ```
  //  * prop.file
  //  * const now = new Date();
  //  * const serial = new Serial(now);
  //  * assert(now.getTime() !== serial.value);
  //  * assert(now.getTime() === serial.toDate().getTime());
  //  * ```
  //  */
  // const prop = Object.keys(Property).reduce((prop, serviceName) => {
  //   //use Object.keys().reduce() to avoid accessing the Property getters
  //   prop[serviceName] = (name, value) => {
  //     const type = Property[serviceName];
  //     if(null===name) return notifyOnPropChange.notify() && retryGoogle(() => type.deleteAllProperties());
  //     if(undefined===name) return retryGoogle(() => type.getProperties()).map(value => JSON.parse(value));
  //     if(undefined===value) return JSON.parse(retryGoogle(() => type.getProperty(name)));
  //     if(null===value) return notifyOnPropChange.notify(name) && retryGoogle(() => type.deleteProperty(name));
  //     notifyOnPropChange.notify(name, value);
  //     return retryGoogle(() => type.setProperty(name, minify(value)));
  //   };//prop[serviceName]
  //   return prop;
  // }, {});//reduce prop

  // /** Read and write to each of the various CacheServices.
  //  * 
  //  * @param {string|string[]|object} name Name of the cache to read/write.
  //  * If a string, the cached value is read/written.
  //  * If an array of strings, the cached values are read/written.
  //  * If an object describing multiple values, it is written to the cache.
  //  * 
  //  * @param {string} [value] Value to write.
  //  * If undefined, the specified cache is retrieved.
  //  * If null, the specified cache is deleted.
  //  * 
  //  * @return {string|undefined}
  //  */
  // const cache = Object.keys(Cache).reduce((cache, serviceName) => {
  //   //use Object.keys().reduce() to avoid accessing the Cache getters
  //   cache[serviceName] = (name, value) => {
  //     const type = Cache[serviceName];
  //     const [ getter, remover ] = is(name, Array) ? [ 'getAll', 'removeAll' ] : [ 'get', 'remove' ];
  //     if(is(name, Object)) return retryGoogle(() => type.putAll(name, _maxCacheTime));
  //     if(undefined===value) return JSON.parse(retryGoogle(() => type[getter](name)));
  //     if(null===value) return retryGoogle(() => type[remover](name));
  //     return retryGoogle(() => type.put(name, minify(value), _maxCacheTime));
  //   };//cache[serviceName]
  //   return cache;
  // }, {});//reduce cache

  // /** Use each of the various LockServices. */
  // const lock = Object.keys(Lock).reduce((lock, serviceName) => {
  //   //use Object.keys().reduce() to avoid accessing the Lock getters
  //   lock[serviceName] = func => {
  //     const beginTryLock = new Date();
  //     const service = Lock[serviceName];
  //     for(let ready=false; !ready;){
  //       assert(!isTimeUp());
  //       if(isTimeUp()){
  //         retryGoogle(() => service.releaseLock());//just in case
  //         log.error(`Times up for ${serviceName} lock after ${Duration({beginTryLock}).as('ms')}ms`);
  //         return TIMESUP;
  //       }//if isTimeUp()
  //       ready = retryGoogle(() => service.tryLock(secToMs(10)));//tryLock returns boolean
  //     }//for ready
  //     assert(service.hasLock());
  //     log(`${serviceName} lock obtained in ${Duration({beginTryLock}).as('ms')}ms`);
  //     const beginHasLock = new Date();
  //     const result = retry(() => func());
  //     retryGoogle(() => service.releaseLock());
  //     log(`${serviceName} lock was retained for ${Duration({beginHasLock}).as('ms')}ms`);
  //     if(is(result, Error)) throw result;//now that we've released the lock we can throw the error
  //     return result;
  //   };//lock[serviceName]
  //   return lock;
  // }, {});//reduce lock

  // /** Use each of the various Trigger services. */
  // const trigger = Object.keys(Trigger).reduce((trigger, serviceName) => {
  //   //use Object.keys().reduce() to avoid accessing the Trigger getters
  //   trigger[serviceName] = (...refs) => {
  //     const service = Trigger[serviceName];
  //     service.getScriptTriggers().filter(trigger => refs.every(ref => {
  //       if(is(ref, ScriptApp.TriggerSource)) return ref==retryGoogle(() => trigger.getTriggerSource());
  //       if(is(ref, ScriptApp.EventType    )) return ref==retryGoogle(() => trigger.getEventType());
  //       if(is(ref.toString(), $TriggerId)) return ref==retryGoogle(() => trigger.getUniqueId());
  //       if(is(ref.toString(), $Id)) return ref==retryGoogle(() => trigger.getTriggerSourceId());
  //       return assert(is(ref, String)) && ref==retryGoogle(() => trigger.getHandlerFunction());
  //     })).forEach(trigger => trigger.delete = () => retryGoogle(() => ScriptApp.deleteTrigger(trigger)));
  //   };//trigger[serviceName]
  //   return trigger;
  // }, {});//reduce trigger

  //add some convenience methods to DriveApp
  if(globalThis.DriveApp){
    assert(_isServer);

    DriveApp.getItemById = id => {
      const test = retryGoogle(() => DriveApp.getFileById(id));
      const type = retryGoogle(() => test.getMimeType());
      switch(type){
        default: return test;
        case MimeType.FOLDER       : return retryGoogle(() => DriveApp      .getFolderById(id));
        case MimeType.GOOGLE_DOCS  : return retryGoogle(() => DocumentApp   .openById     (id));
        case MimeType.GOOGLE_FORMS : return retryGoogle(() => FormApp       .openById     (id));
        case MimeType.GOOGLE_SHEETS: return retryGoogle(() => SpreadsheetApp.openById     (id));
        case MimeType.GOOGLE_SLIDES: return retryGoogle(() => SlidesApp     .openById     (id));
      }//switch type
    };//DriveApp.getItemById

    DriveApp.getItemByUrl = url => DriveApp.getItemById(url.match($Id).pop());

    DriveApp.getIdFromPath = path => path.match($Path).reduce(
      (item, name, i, arr) => retryGoogle(
        () => item[`get${i==arr.length-1 ? 'Files' : 'Folders'}ByName`](name)
      ).asArray().uno, 
      retryGoogle(() => DriveApp.getRootFolder())
    );//reduce item

    DriveApp.getItemByPath = path => DriveApp.getItemById(DriveApp.getIdFromPath(path));

    //get Drive item by id, url, or path
    DriveApp.getItem = desc => is(desc, $Path) 
      ? DriveApp.getItemByPath(desc) 
      : DriveApp.getItemById(desc.match($Id).pop());//handle urls too

    // /** Internal cached storage for spreadsheet data. Keyed by ssId then dataType. */
    // const _DriveCache = {};
  }//if DriveApp

  /** Upgrade the given Google ``Spreadsheet`` with added functionality.
   * @param {Spreadsheet} [spreadsheet] The spreadsheet to upgrade. If undefined,
   *        the active spreadsheet is upgraded, and for convenience, this ``ss`` 
   *        function is given all the members of the upgraded spreadsheet too.
   * @return {Spreadsheet} With the added functionality.
   * @example
   * ```
   * ss().read({ 'Users': ['values','notes'] });//bulk read all values and notes from 'Users' sheet
   * ss['Users'].col['Name'].values[5] = 'edited';
   * ss['Users'].col['Name'].values.write();
   * ```
   * @example
   * ```
   * const menu = ss(SpreadsheetApp.openById(id)).read({ 'Lunch': ['values','notes'] });
   * menu['Lunch'].col['Cost'].values[5] = 3.99;
   * menu['Lunch'].col['Cost'].values.write();
   * ```
   */
  const ss = spreadsheet => {
    if(spreadsheet && spreadsheet._wasUpgraded) return spreadsheet;//given spreadsheet already upgraded
    if(!spreadsheet && ss._wasUpgraded) return ss;//we already upgraded the active spreadsheet
    const _ss = spreadsheet ? {} : ss;//if using active spreadsheet, upgrade this ss function itself!
    if(!spreadsheet) spreadsheet = profile(
      () => retryGoogle(() => SpreadsheetApp.getActiveSpreadsheet()),
      { desc: `SpreadsheetApp.getActiveSpreadsheet()` }
    );//profile
    Object.assign(_ss, spreadsheet);
    Object.defineProperty(_ss, '_wasUpgraded', { value: true });//remember that we upgraded this
    //support reading the spreadsheet in bulk, returning _ss for chaining
    _ss.read = desc => (Object.keys(desc).forEach(sheetName => {
      //support indexing on sheets to access data by types; eg: ss['Users'].values
      const sheet = profile(
        () => retryGoogle(() => spreadsheet.getSheetByName(sheetName)), 
        { desc: `ss.getSheetByName('${sheetName}')` }
      );//profile
      const dataRange = profile(
        () => retryGoogle(() => sheet.getDataRange()),
        { desc: `ss['${sheetName}'].getDataRange()` }
      );//profile
      const dataRangeAddress = retryGoogle(() => dataRange.getA1Notation());
      const s = Object.assign(dataRange, sheet);//s is a sheet with methods from data Range
      Object.assign(_ss, { [sheetName]: s });
      desc[sheetName].forEach(dataType => {
        const dataName = dataType.slice(0,1).toUpperCase()+dataType.slice(1);
        assert('function'==typeof dataRange['get'+dataName], `"${'get'+dataName}" is not a Range method.`);
        profile(
          () => s[dataType] = retryGoogle(() => dataRange['get'+dataName]()),//eg: getValues()
          { desc: `ss['${sheetName}'].getRange('${dataRangeAddress}').get${dataName}()` }
        );//profile
        s[dataType].write = data => profile(
          () => retryGoogle(() => dataRange['set'+dataName](data)),//eg: setValues(data)
          { desc: `ss['${sheetName}'].getRange('${dataRangeAddress}').set${dataName}(${stringify(data)})` }
        );//profile
      });//forEach dataType
      //support quick access to a sheet's headings; eg: ss['Users'].headings
      const headingRow = Math.max(0, retryGoogle(() => s.getFrozenRows())-1);
      s.headings = desc[sheetName].filter(type => type=='values').length 
        ? s.values[headingRow]
        : retryGoogle(() => s.getRange('1:1').getValues()[headingRow]);
      s.headings.row = 1+headingRow;
      //support accessing a column, indexible by its heading; eg: ss['Users'].col['Name'].values
      s.col = s.headings.reduce((col, heading, index) => {
        if(col[heading]) log.warn(`ss: Overwriting column heading: "${heading}"`);
        const number = 1+index;
        const letter = colNumToLet(number);
        const colRange = retryGoogle(() => s.getRange(letter+':'+letter));
        return Object.assign(col, {
          [heading]: Object.assign(
            desc[sheetName].reduce((data, dataType) => {
              const dataName = dataType.slice(0,1).toUpperCase()+dataType.slice(1);
              const c = assert(s.headings.indexOf(heading)+1)-1;
              return Object.assign(data, { 
                [dataType]: Object.assign(transpose(s[dataType])[c], {
                  write: data => retryGoogle(() => colRange['set'+dataName](data))//eg: setValues(data)
                })//write
              });//Object.assign data
            }, {}),//reduce data
            sheet,//give the col the methods from the sheet
            colRange,//give the col the methods from the column Range
            { heading, number, index, letter }//easy references
          )//Object.assign
        });//reduce data
      }, {});//reduce col
      //support automatically combining all data types into a single table; eg: ss['Users'].combined
      s.combined = desc[sheetName]
      .reduce((combined, dataType) => (s[dataType]
        .map((row, r) => [
          ...combined.length ? combined[r] : [], 
          ...s.headings.row-1<r ? row : row.map((_, c) => `${s.headings[c]}#${dataType}`)
        ])//map row
      ), []);//reduce combined
    }), _ss);//ss.read returns _ss for chaining
    return _ss;
  };//ss

  /** @typedef {Symbol} Column */
  const Column = Array(26*27).fill(0).reduce((Column, _, i) => {
    const [ number, letter ] = [ 1+i, colNumToLet(1+i) ];
    Column[number] = Symbol(number);
    Column[letter] = Symbol(letter);
    return Column;
  }, {});//Column

  // /** @typedef {string} SheetDataType */
  // const SheetDataType = ENUM([
  //   'background',
  //   'backgrounds',
  //   'backgroundObject',
  //   'backgroundObjects',
  //   'dataValidation',
  //   'dataValidations',
  //   'fontColorObject',
  //   'fontColorObjects',
  //   'fontFamily',
  //   'fontFamilies',
  //   'fontLine',
  //   'fontLines',
  //   'fontSize',
  //   'fontSizes',
  //   'fontStyle',
  //   'fontStyles',
  //   'fontWeight',
  //   'fontWeights',
  //   'formula',
  //   'formulas',
  //   'formulaR1C1',
  //   'formulasR1C1',
  //   'horizontalAlignment',
  //   'horizontalAlignments',
  //   'note',
  //   'notes',
  //   'numberFormat',
  //   'numberFormats',
  //   'richTextValue',
  //   'richTextValues',
  //   'textDirection',
  //   'textDirections',
  //   'textRotation',
  //   'textRotations',
  //   'textStyle',
  //   'textStyles',
  //   'value',
  //   'values',
  //   'verticalAlignment',
  //   'verticalAlignments',
  //   'wrapStrategies',
  //   'wrapStrategy',
  //   'wrap',
  //   'wraps',
  // ]);//SheetDataType

  /** Convert Spreadsheet sheets into tables.
   * ```
   * const { skus, prices } = getTables().values.products;
   * skus.forEach((sku, i) => 'X'==sku && prices[i]+=10);
   * prices.write();
   * ```
   * @param {options} [options]
   * @property {Spreadsheet|string} [options.spreadsheet] Defaults to the active Spreadsheet.
   *  May be a string id or url.
   * @property {Array<Sheet|string>} [options.sheets] Defaults to every sheet in the Spreadsheet.
   * @property {SheetDataType[]} [options.dataTypes] The types of spreadsheet data to read. 
   *  Defaults to only values.
   * @property {boolean} [options.ignoreCache] By default, cached data will be used, but it can be ignored.
   * @return {tables} Returns an array of tables. A table is an array of columns. 
   *  A column is an array of values.
   * @property {Array<Array<Array<*>>>} [tables.values]
   */
  const getTables = ({
    spreadsheet = SpreadsheetApp.getActive(), 
    sheets = 'ALL', 
    dataTypes = [ SheetDataType.values, ], 
    ignoreCache = false
  } = {}) => {
    if(is(spreadsheet, $Id)) spreadsheet = SpreadsheetApp.openById(spreadsheet);
    if(!is(sheets, Array)) sheets = spreadsheet.getSheets();
    else sheets = sheets.map(s => is(s, String) ? spreadsheet.getSheetByName(s) : s);
    const ssId = spreadsheet.getId();
    if(Sheets && Settings.useBatchGet) log.warn('batchGet not yet implemented');
    //{ values:[ [ ..., heading:string ], ..., sheet:Sheet ], ..., spreadsheet:Spreadsheet }
    const tables = dataTypes.reduce((tables, type) => {
      tables[type] = sheets.map(sheet => {
        const sheetName = sheet.getName();
        const cached = $($(_DriveCache, ssId, {}), type, {});
        if(!ignoreCache && cached[sheetName]) return cached[sheetName];//👍 CACHE HIT
        const headingRow = Math.max(1, sheet.getFrozenRows());
        const typeName = type[0].toUpperCase() + type.slice(1);
        const [ getter, setter ] = [ 'get' + typeName, 'set' + typeName ];
        const name = sheetName.toCamelCase();
        const range = sheet.getDataRange();
        // log(`get${typeName}('${sheetName}'!${range.getA1Notation()})`);
        let table = range[getter]();//⏱ EXPENSIVE READ HAPPENS HERE!!!
        const headings = table.slice(0, headingRow).reverse().transpose().map(col => col.filter(x => x)[0]||'');
        // log('headings: '+stringify(headings));
        table.splice(0, headingRow);//remove frozen rows to make column easily iterable
        table.unshiftEmpty(1+headingRow);//use empty to make row indices match actual row numbers
        table = cached[sheetName] = table.transpose();//columns come before rows in our tables
        table.unshiftEmpty();//use empty to make column indices match actual column numbers
        table.forEach((column, c) => {
          column.number = c;
          column.letter = colNumToLet(column.number);
          column.heading = headings[c-1].toString();
          column.name = column.heading.toCamelCase();
          column.headingRow = headingRow;
          column.dataType = type;
          column.table = table;
          column.sheet = sheet;
          column.spreadsheet = spreadsheet;
          column.getRange = () => 
            sheet.getRange(headingRow+1, 1, column.length-headingRow-1, 1);
          column.write = (value = undefined) => 
            column.getRange()[setter](is(value, undefined) ? column.nonempty().map(x => [x]) : value);
          if(table[column.name]) log.warn(`Duplicate column headings found: '${sheetName}'!'${column.heading}'`);
          table[       column.name   ] = //give the table a property for each column name
          table[Column[column.letter]] = //also for each column letter using symbols to prevent collisions
          table[Column[column.number]] = //also for each column number using symbols to prevent collisions
          column;
        });//forEach column
        table[PUBLIC] = { name, sheet, spreadsheet };//prevent collisions with column names
        table[PUBLIC].getRange = () => 
          sheet.getRange(headingRow+1, 1, sheet.getLastRow()-headingRow, sheet.getLastColumn());
        table[PUBLIC].write = (value = undefined) => 
          table[PUBLIC].getRange()[setter](is(value, undefined) ? table.nonempty().transpose().nonempty() : value);
        return table;
      });//map sheet
      tables[type].forEach(table => tables[type][table[PUBLIC].name] = table);//assign table names
      tables[type][PUBLIC] = { spreadsheet };//prevent collisions with table names
      return tables;
    }, {});//reduce tables
    //getTables().values.Sheet1.serialNumber.write();
    tables.spreadsheet = spreadsheet;
    return tables;
  };//getTables

  /** Entrypoint for all triggers made by mr. */
  const _onTrigger = e => {
    setEntryType(EntryType.trigger);
    const pickedJob = _pickTriggerJob();//script lock done here
    const updatedJob = _work(pickedJob);//⏱EXPENSIVE WORK DONE HERE!!!
    _updateTriggerJob(updatedJob);//script lock done here
  };//_onTrigger

  /** Pick a trigger job that needs to be worked on. */
  const _pickTriggerJob = () => lock.file(() => {
    const allJobs = cache.file('🧰TriggerJobs');
    //TODO: more sophisticated job scheduler: sort by oldest?
    const pickedJob = allJobs.reduce((pickedJob, job, i) => (
      //remove the picked job from allJobs and return it
      pickedJob || (!job.done && allJobs.splice(i, 1))
    ), null);//reduce pickedJob
    cache.file('🧰TriggerJobs', allJobs);
    return pickedJob;
  });//lock.file

  /** Update a trigger job that has been worked on. */
  const _updateTriggerJob = job => lock.file(() => {
    const allJobs = cache.file('🧰TriggerJobs');
    allJobs.push(job);
    cache.file('🧰TriggerJobs', allJobs);
    const allDone = allJobs.every(job => job.done);
    if(allDone) trigger.script(_onTrigger.name, ScriptApp.TriggerSource.CLOCK).delete();
  });//lock.file

  //#endregion DRIVE
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region KAROS CLIENT

  /** Placeholder for widget tree state machine functions. */
  const _karos = {};

  const dom = (selectors, on=document) => [ ...on.querySelectorAll(selectors) ];
  
  // /** DOM helpers. */
  // const dom = {
  //   /** Find doms with the given selectors. */
  //   select: selectors => [ ...document.querySelectorAll(selectors) ],
  //   /** Get all the html comments. */
  //   comments: (root=document.body) => 
  //     document.createNodeIterator(
  //       root, 
  //       NodeFilter.SHOW_COMMENT, 
  //       () => NodeFilter.FILTER_ACCEPT, 
  //       false
  //     ).asArray(),
  //   /** */
  //   data: (dom, data) => JSON.parse(dom.getAttribute('data-'+data)),
  //   /** */
  //   call: (selectors, event) => dom.select(selectors).forEach(dom => {
  //     const funcName = dom.getAttribute('data-'+event.name);
  //     const func = funcName && _karos[funcName];
  //     if(is(func, Function)) return func(event);
  //   }),//call
  //   /** */
  //   events: [
  //     "oncopy",              "oncut",                     "onpaste",                  "onabort",
  //     "onblur",              "onfocus",                   "onauxclick",               "onbeforeinput",
  //     "oncanplay",           "oncanplaythrough",          "onchange",                 "onclick",
  //     "onclose",             "oncontextmenu",             "oncuechange",              "ondblclick",
  //     "ondrag",              "ondragend",                 "ondragenter",              "ondragexit",
  //     "ondragleave",         "ondragover",                "ondragstart",              "ondrop",
  //     "ondurationchange",    "onemptied",                 "onended",                  "onformdata",
  //     "oninput",             "oninvalid",                 "onkeydown",                "onkeypress",
  //     "onkeyup",             "onload",                    "onloadeddata",             "onloadedmetadata",
  //     "onloadend",           "onloadstart",               "onmousedown",              "onmouseenter",
  //     "onmouseleave",        "onmousemove",               "onmouseout",               "onmouseover",
  //     "onmouseup",           "onwheel",                   "onpause",                  "onplay",
  //     "onplaying",           "onprogress",                "onratechange",             "onreset",
  //     "onresize",            "onscroll",                  "onsecuritypolicyviolation","onseeked",
  //     "onseeking",           "onselect",                  "onslotchange",             "onstalled",
  //     "onsubmit",            "onsuspend",                 "ontimeupdate",             "onvolumechange",
  //     "onwaiting",           "onselectstart",             "onselectionchange",        "ontoggle",
  //     "onpointercancel",     "onpointerdown",             "onpointerup",              "onpointermove",
  //     "onpointerout",        "onpointerover",             "onpointerenter",           "onpointerleave",
  //     "ongotpointercapture", "onlostpointercapture",      "onmozfullscreenchange",    "onmozfullscreenerror",
  //     "onanimationcancel",   "onanimationend",            "onanimationiteration",     "onanimationstart",
  //     "ontransitioncancel",  "ontransitionend",           "ontransitionrun",          "ontransitionstart",
  //     "onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart",   "onwebkittransitionend",
  //     "onerror",             "onfullscreenchange",        "onfullscreenerror",
  //   ],//events
  // };//dom

  // /** Define all the karos css classes that will have special functionality. */
  // const karosDomClasses = ENUM({
  //   karos: '.karos',
  //   jobsList: '.karosJobsList',
  // });//karosDomClasses

  // /** Client-side list of pending jobs. */
  // const _pendingJobs = [];
  // const pendingJobs = {

  //   /** Get all the jobs with the given ids, or all the jobs.
  //    * @param {number[]} [ids]
  //    * @return {object[]}
  //    */
  //   get: ids => ids ? ids.map(id => assert(_pendingJobs.filter(job => id==job.created).uno)) : _pendingJobs,

  //   /** Add a job.
  //    * @param {object} job
  //    */
  //   add: job => {
  //     _pendingJobs.push(job);
  //     assert(_pendingJobs.length==[ ...new Set(_pendingJobs.map(job => job.created)) ].length);
  //     dom.select(karosDomClasses.jobsList).forEach(jobList => {
  //       const addJobMethodName = assert(dom.data(jobList, new Error('addJob')));
  //       const addJobMethod = assert(window[addJobMethodName]);
  //       addJobMethod(job);
  //     });//forEach jobList
  //   },//add

  //   /** Mark a job as done.
  //    * @param {object} job
  //    */
  //   done: job => {
  //     assert(_pendingJobs.length==[ ...new Set(_pendingJobs.map(job => job.created)) ].length);
  //     const i = _pendingJobs.findIndex(finishedJob => finishedJob.created==job.created);
  //     assert(_pendingJobs.splice(i, 1)==job.created);
  //     dom.select(karosDomClasses.jobsList).forEach(jobList => {
  //       const jobDoneMethodName = assert(dom.data(jobList, new Error('jobDone')));
  //       const jobDoneMethod = assert(window[jobDoneMethodName]);
  //       jobDoneMethod(job);
  //     });//forEach jobList
  //   },//done
  // };//karosJobList

  // /** Create a new job that does nothing but gives the server an opportunity to send data.
  //  * If there are no jobs then we can afford to wait longer for state changes.
  //  */
  // const _karosGetStateJob = () => setTimeout(() => createJobs([{}]), _pendingJobs.length ? 250 : 4137);

  // /** Create some jobs on the server. */
  // const createJobs = jobs => {
  //   //update each job with a unique 'created' property (number)
  //   jobs.forEach(job => {
  //     let created = DateTime.now().valueOf();//number of milliseconds
  //     while(_pendingJobs.some(job => job.created==created)) ++created;//guarantee 'created' is unique
  //     job.created = created;
  //     pendingJobs.add(job);
  //   });//forEach job
  //   const _onFailure = err => {
  //     log.error(`❌ createKarosJobs failed: ${stringify(err)})`);
  //     const failedJobIds = JSON.parse(err.message.match(/«jobs:(.+)»/).pop());//job ids hidden here
  //     const failedJobs = _pendingJobs.filter(job => failedJobIds.includes(job.created));
  //     failedJobs.forEach(failedJob => {
  //       if(is(failedJob.onFailure, Function)) return failedJob(failedJob, err);
  //       log.warn('Missing job.onFailure which is needed to re-add the job.');
  //     });//forEach failedJob
  //   };//_karosOnFailure
  //   const _onSuccess = completedJobs => {
  //     //translate the given jobs to ones found in our pending list so that job.onSuccess exists
  //     completedJobs = completedJobs.map(completedJob => 
  //       assert(_pendingJobs.filter(job => job.created==completedJob.created).uno)
  //     );//map completedJob
  //     completedJobs.forEach(job => {
  //       if(_getKarosState.name==job.worker);//🔥 if response is a state change.......
  //       pendingJobs.jobDone(job);
  //       if(is(job.onSuccess, Function)) return job.onSuccess(job);
  //       log.warn('Missing job.onSuccess');
  //     });//forEach response
  //     _karosGetStateJob();
  //   };//_onSuccess
  //   google.script.run//.withUserObject(job)
  //   .withFailureHandler(_onFailure)
  //   .withSuccessHandler(_onSuccess)
  //   .request(jobs);
  // };//createJobs

  /** Initialize after the DOM is fully loaded. */
  const _initClient = e => {
    assert(_isClient);
    log.configure({
      pre: `${id}${setEntryType(EntryType.client).name}`, 
      post: `\n» ${user}`,
    });//log.configure
    log('DOMContentLoaded');
    M.AutoInit();//initialize materialize
    // dom('.collapsible.expandable.closed').forEach(el => M.Collapsible.init(el, { accordion: false }));

    // //set up the _pendingJobs array with what we find in the job lists doms
    // //TODO: what if the user doesnt have a dom list? can server send back jobs another way?
    // dom.select(karosDomClasses.jobsList).forEach(jobList => {
    //   const getJobsMethodName = assert(dom.data(jobList, new Error('getJobs')));
    //   const getJobsMethod = assert(window[getJobsMethodName]);
    //   getJobsMethod().forEach(job => _pendingJobs.push(job));
    // });//forEach jobList
    // _karosGetStateJob();//kick things off with a getState job request
    // //set up the 'onClick' event on all '.karos' doms
    // dom.select('.karos').forEach(el => true
    //   && el.dataset.onClick
    //   && 'function'==typeof _karos[el.dataset.onClick]
    //   && (el.onclick = _karos[el.dataset.onClick])
    // );//forEach dom
    // //it's time to fire the 'onLoadDone' event across all '.karos' doms
    // dom.call(karosDomClasses.karos, { name: 'onLoadDone' });
  };//_initClient

  //when the page is done loading, set up karos
  if(globalThis.window) globalThis.window.addEventListener('DOMContentLoaded', _initClient);

  //#endregion KAROS CLIENT
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region KAROS ☁BACKEND

  // const include = filename => {
  //   try{ return HtmlService.createHtmlOutputFromFile(filename).getContent() }
  //   catch(e){
  //     if(overrideLibName===libState.name.toLowerCase()) return release.include(filename);
  //     throw e;
  //   }//catch
  // };//include

  /** */
  // const _doGetPost = e => {
  //   log(stringify(e));
  //   return ContentService.createTextOutput(`You have ${
  //     DriveApp.getRootFolder().getFolders().asArray().length
  //   } folders!`);
  // };//_doGetPost
  
  // const doGet = _doGetPost;
  // const doPost = _doGetPost;

  /** */
  const _states = [];//e.g: { name:string, type:string, old:*, new:* }
  const states = {
    /** Get state changes. */
    getChanges: () => _states.filter(state => state.old!=state.new),
    /** */
    create: descriptors => {
      const notifier = notification => _states.filter(
        state => state.name==notification.name
      ).uno.new = notification.new;
      const props = prop.script();
      descriptors.forEach(desc => {
        const descType = desc.match(/^([^\.=$ ]+)/).pop();
        const type = SheetDataType[descType] || 'prop';
        const name = desc.match(/^([^=$ ]+)/).pop();
        if('prop'==type){
          const old = props[name];
          notifyOnPropChange.create({ name, notifier, old });//dupes will be ignored
          if(!_states.some(state => state.name==name)) _states.push({ desc, name, type, old });
        }else{
          const numDots = desc.count('.');
          const [ _, dataType, sheetName, heading ] = desc.match(/[^ =]+/).pop().split('.');
          const tables = getTables({ spreadsheet: ss, sheets: 'ALL', dataTypes: [ dataType ] });
          const old = tables[dataType][sheetName][heading];
          if(!_states.some(state => state.name==name)) _states.push({ desc, name, type, old });
        }//else
      });//forEach desc
    },//create
  };//states

  const _karosStates = [];//🔥 use same array for both server and client?

  // /** Request the server does a job and return all completed jobs, which may not include the given job. */
  // const request = (job, startNow = true) => {
  //   job = startNow && !isTimeUp() ? _work(job) : job;
  //   return lock.file(() => {
  //     const allJobs = [ ...(cache.file('🧰TriggerJobs')||[]), job ];
  //     const [ done, active ] = allJobs.split(job => job.done ? 0 : 1);
  //     cache.file('🧰TriggerJobs', active);
  //     //if needed and doesn't already exist, create an everyMinute trigger to finish our jobs
  //     if(active.length) null
  //       || trigger.script(_onTrigger.name, ScriptApp.TriggerSource.CLOCK).uno
  //       || ScriptApp.newTrigger(_onTrigger.name).timeBased().everyMinutes(1).create();
  //     log('request: everyMinute trigger: '+trigger.getUniqueId());
  //     return done;
  //   });//lock.file
  // };//request

  // /** Perform expensive work operations and store the results in cache. */
  // const _work = job => {
  //   if(!job.worker) job.done = true;
  //   if(job.done) return job;
  //   const taskTimes = Object.assign([], { avg: () => taskTimes.length ? taskTimes.average() : undefined });
  //   const WORKER_FUNCTION = globalThis[job.worker] || this[job.worker];
  //   job.tasks.map(task => {
  //     if(task.done || isTimeUp(taskTimes.avg())) return;
  //     taskTimes.push(profile(() => task.result = WORKER_FUNCTION(task, job),//⏱ EXPENSIVE WORK DONE HERE!
  //       { desc: 'job.func(task)', shouldLog: false }).duration.as('ms')
  //     );//taskTimes.push
  //     task.done = true;
  //   });//map task
  //   if(job.tasks.every(task => task.done)) job.done = true;
  //   return job;
  // };//_work

  const _getKarosState = () => 1;//🔥

  //#endregion KAROS ☁BACKEND
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region KAROS 💧FRONTEND

  //frontend responds ASAP with default 

  const user = _isServer 
    ? retryGoogle(() => Session.getActiveUser().getEmail()) 
    : uno(dom('meta[data-user]')).dataset.user;
  const url = _isServer 
    ? retryGoogle(() => ScriptApp.getService().getUrl())
    : uno(dom('meta[data-url]')).dataset.url;
  const id = _isServer
    ? encode(now % encode.max4)
    : uno(dom('meta[data-id]')).dataset.id;
  const _defaultTitle = 'App';
  const _defaultFavicon = 'https://cdn-icons-png.flaticon.com/512/148/148905.png';
  const favicon = `https://cdn-icons-png.flaticon.com/512/3666/3666231.png`;

  /** */
  const doGet = (e = { debug:true, parameter:{ } }) => {
    log.configure({
      pre: `${id}${setEntryType(EntryType.webappFrontend).name}`,  
      post: `\n» ${user}`,
    });//log.configure
    const page = tree.getPage(e.parameter);
    const response = retry(() => page.go({/*additional args may go here*/}));
    return response instanceof Error 
      ? doError(`Page "${page.config.name}" failure:`, response.stack) 
      : response;
  };//doGet

  /** */
  function backendRequest({ 
    time = now,
    who = user,
    id = 'DEBUG',
    request,
  }={}){
    const params = { 
      method: 'post', 
      contentType: 'application/json', 
      headers: { Authorization: `Bearer `+retryGoogle(() => ScriptApp.getOAuthToken()) }, 
      muteHttpExceptions: true, 
      payload: minify(arguments[0]),
    };//options
    const httpResponse = retryGoogle(() => UrlFetchApp.fetch(_backend, params));
    const code = httpResponse.getResponseCode();
    assert(200<=code && code<300, new Error('Response code: '+code));
    return JSON.parse(httpResponse.getContentText());
  };//backendRequest

  let _currentData = null;
  const include = pageName => (_currentData
    ? Object.assign(HtmlService.createTemplateFromFile(pageName), { data:_currentData }).evaluate()
    : HtmlService.createHtmlOutputFromFile(pageName)
  ).getContent();

  function WidgetTree({ widgets }={}){
    if(!new.target) return new WidgetTree(arguments[0]);
    this.config = { ...arguments[0]||{} };//remember everything passed in
    this.config.tree = this;
    this.config.widgets = (this.config.widgets||[])
    .map(widgetConfig => new Widget({ ...this.config, ...widgetConfig }));//share tree config info w/ widgets
    this.args = { ...this.config };//only certain things are "arguments"
    delete this.args.tree;//get rid of unnecessary or circular references
    delete this.args.widgets;
  };//WidgetTree

  WidgetTree.prototype.getPage = function(params){
    return this.config.widgets.filter(widget => widget
      // && (log(stringify(widget)),true)
      && 'page'==widget.config.type
      && null!=params[widget.config.name]
    )[0]||this.config.widgets[0];//always assume the first widget that was defined is 'Home'
  };//getPage

  function Widget({ tree, name, title, type, img, menu=true, request }={}){
    if(!new.target) return new Widget(arguments[0]);
    this.config = { ...arguments[0]||{} };//remember everything passed in
    this.args = { ...this.config };//only certain things are "arguments"
    delete this.args.tree;//get rid of unnecessary or circular references
    delete this.args.widgets;
  };//Widget

  Widget.prototype.go = function(args){
    log('Widget.go: '+this.config.name);
    const template = HtmlService.createTemplateFromFile(this.config.name);
    const combinedArgs = { ...this.args, ...{ id, time:now, who:user }, ...args };
    this.response = this.config.request && backendRequest(combinedArgs);
    template.data = _currentData = { id, url, user, ...this.config, ...combinedArgs, response:this.response };
    if(this.response && this.response.isError) throw new Error(
      `\n\nServer:\n\n${this.response.stack}\n\nClient:`
    );//Error
    const evaluated = retry(() => template.evaluate());//may invoke include() which uses _currentData
    if(!evaluated) throw new Error('Failed to evaluate file: '+this.config.name);
    if(evaluated instanceof Error) throw evaluated;
    if(null!=evaluated.switchPage){
      log('🔀 Switching page from "'+this.config.name+'" to "'+evaluated.switchPage+'"');
      return this.config.tree.config.widgets
      .filter(p => evaluated.switchPage==p.config.name)[0](combinedArgs);
    }//if switchPage
    const title = this.config.title || (
      log.warn(`Page "${this.config.name}" will use the default title.`), 
      _defaultTitle
    );//title
    const favicon = this.config.favicon || (
      log.warn(`Page "${this.config.name}" will use the default favicon.`), 
      _defaultFavicon
    );//favicon
    const html = evaluated
    .setFaviconUrl(favicon)
    .setTitle(title)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
    log('✅ '+this.config.name);
    return html;
  };//Widget.prototype.go

  const switchPage = name => error({ switchPage: name });

  /** */
  const doError = (title, msg) => {
    const html = HtmlService.createTemplateFromFile('error');
    html.title = title;
    html.msg = msg;
    html.who = user;
    log.error(`❌ ${title} ${msg}`);
    return html.evaluate()
    .setTitle(`Wilford.family`)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  };//doError

  const tree = WidgetTree({ id, widgets: [
    /** */
    { name: 'home', 
      title: 'Home', 
      type: 'page',
      favicon,
      request: ({ who }) => Lock.Document.criticalSection(() => {
        const ss         = retryGoogle(() => SpreadsheetApp.getActiveSpreadsheet());
        const users      = retryGoogle(() => ss.getSheetByName('Users').getDataRange());
        const perms      = retryGoogle(() => ss.getSheetByName('PermissionOverrides').getDataRange());
        const userValues = retryGoogle(() => users.getValues());
        const permValues = retryGoogle(() => perms.getValues());
        const cols = {
          users: { 
            home : userValues[0].indexOf('Home' ), 
            email: userValues[0].indexOf('Email'), 
          },//users
        };//cols
        assert(0<=cols.users.home && 0<=cols.users.email);
        const userMatch = uno(userValues.filter(row => 
          row[cols.users.email].toLowerCase().includes(who)
        ));//filter row
        const forbidden = !userMatch && !permValues.includes(who);
        return !forbidden;
      }),//Lock.Document.criticalSection
    },//Widget home
    /** */
    { name: 'deny', 
      menu: false,
      title: 'Permission denied',
      type: 'page',
      favicon,
    },//Widget deny
    /** */
    { name: 'info', 
      title: 'Household information', 
      type: 'page',
      favicon,
      request: ({ who }) => Lock.Document.criticalSection(() => {
        const ss         = retryGoogle(() => SpreadsheetApp.getActiveSpreadsheet());
        const users      = retryGoogle(() => ss.getSheetByName('Users').getDataRange());
        const homes      = retryGoogle(() => ss.getSheetByName('Homes').getDataRange());
        const perms      = retryGoogle(() => ss.getSheetByName('PermissionOverrides').getDataRange());
        const userValues = retryGoogle(() => users.getValues());
        const userNotes  = retryGoogle(() => users.getNotes ());
        const homeValues = retryGoogle(() => homes.getValues());
        const homeNotes  = retryGoogle(() => homes.getNotes ());
        const permValues = retryGoogle(() => perms.getValues());
        const cols = {
          homes: { 
            home : homeValues[0].indexOf('Home' ), 
          },//homes
          users: { 
            home : userValues[0].indexOf('Home' ), 
            email: userValues[0].indexOf('Email'), 
          },//users
        };//cols
        assert(0<=cols.homes.home && 0<=cols.users.home && 0<=cols.users.email);
        const userMatch = uno(userValues.filter(row => 
          row[cols.users.email].toLowerCase().includes(who)
        ));//filter row
        const forbidden = !userMatch && !permValues.includes(who);
        if(forbidden) return (log('FORBIDDEN!'), false);
        const appendHomeNotes = homeNotes.map((row, r) => r ? row : homeValues[0].map(h => h+'#Note'));
        const appendUserNotes = userNotes.map((row, r) => r ? row : userValues[0].map(h => h+'#Note'));
        const homeTable = homeValues.map((row, r) => [ ...row, ...appendHomeNotes[r] ]);
        const userTable = userValues.map((row, r) => [ ...row, ...appendUserNotes[r] ]);
        const results = tableToObjects(homeTable, { replacer: (r, heading, value) => 
          'Occupants'!=heading ? value : tableToObjects(userTable.filter((userRow, i) => 
            !i || homeTable[r][cols.homes.home]===userRow[cols.users.home]
          ))//tableToObjects
        });//tableToObjects
        return results;
      })//Lock.Document.criticalSection
    },//Widget info
    /** */
    { name: 'trip', 
      title: 'Family trips', 
      type: 'page',
      favicon,
      request: ({ who }) => Lock.Document.criticalSection(() => {
        const ss         = retryGoogle(() => SpreadsheetApp.getActiveSpreadsheet());
        const users      = retryGoogle(() => ss.getSheetByName('Users').getDataRange());
        const trips      = retryGoogle(() => ss.getSheetByName('Trips').getDataRange());
        const perms      = retryGoogle(() => ss.getSheetByName('PermissionOverrides').getDataRange());
        const userValues = retryGoogle(() => users.getValues());
        const userNotes  = retryGoogle(() => users.getNotes ());
        const tripValues = retryGoogle(() => trips.getValues());
        const tripNotes  = retryGoogle(() => trips.getNotes ());
        const permValues = retryGoogle(() => perms.getValues());
        //determine which columns we need access to
        const cols = {};
        cols.users = { 
          name : userValues[0].indexOf('Name' ), 
        //home : userValues[0].indexOf('Home' ), 
          email: userValues[0].indexOf('Email'), 
        };//cols.users
        cols.trips = transpose(userValues)[cols.users.name]
        .slice(1).reduce((obj, userName) => (
          assert(!obj.hasOwnProperty(userName)),
          { ...obj, [userName]: tripValues[0].indexOf(userName) }
        ), {});//reduce
        //determine if we are forbidden or not
        const userMatch = uno(userValues.filter(row => 
          row[cols.users.email].toLowerCase().includes(who)
        ));//filter row
        const forbidden = !userMatch && !permValues.includes(who);
        if(forbidden) return (log(`${who} is forbidden`), false);
        const appendUserNotes = userNotes.map((row, r) => r ? row : userValues[0].map(h => h+'#Note'));
        const appendTripNotes = tripNotes.map((row, r) => r ? row : tripValues[0].map(h => h+'#Note'));
        const tripTable = tripValues.map((row, r) => [ ...row, ...appendTripNotes[r] ]);
        const userTable = userValues.map((row, r) => [ ...row, ...appendUserNotes[r] ]);
        const results = tableToObjects(tripTable, { replacer: (r, heading, value) => 
          'Attendees'!=heading ? value : tableToObjects(userTable.filter((row, i) => 
            !i || tripTable[r][tripTable[0].indexOf(row[cols.users.name])]
          ))//tableToObjects
        });//tableToObjects
        results.forEach(result => Object.keys(cols.trips).forEach(name => delete result[name]));
        return results;
      })//Lock.Document.criticalSection
    },//Widget trip
  ]});//WidgetTree

  //#endregion KAROS 💧FRONTEND
  //////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////
  //#region EXPORT
  const _clientEx = !_isClient ? {} : {
    //🌈client only exports go here
  };//_clientExports
  const _frontendEx = !_isFrontend ? {} : {
    //💧frontend only exports go here
    doGet           , backendRequest  , include         , switchPage      ,
    WidgetTree      , Widget          ,
  };//_serverFrontendExports
  const _backendEx = !_isBackend ? {} : {
    //⛅backend only exports go here
    doPost          ,
  };//_serverBackendExports
  const _serverEx = !_isServer ? {} : {
    //⛅💧both frontend and backend exports go here
    doGet           , backendRequest  , include         , switchPage      ,
    Trigger         , Property        , Cache           , Lock            ,
    UI              , ss              , getScriptUrl    , retryGoogle     ,
    // CS           , prop            , cache           , trigger         ,
    // states       , getTables       ,
  };//_serverExports
  return Object.assign(callerGlobalThis, _clientEx, _frontendEx, _backendEx, _serverEx, {
    //exports for everything go here
    doGet           , backendRequest  , include         , switchPage      ,
    asciiA          , nbsp            , nbtab           , getCallstack    ,
    msPerSec        , msPerMin        , msPerHr         , msPerDay        ,
    secPerMin       , secPerHr        , secPerDay       , minPerHr        ,
    minPerDay       , hrPerDay        , msToSec         , msToMin         ,
    msToHr          , msToDay         , secToMin        , secToHr         ,
    secToDay        , minToHr         , minToDay        , hrToDay         ,
    secToMs         , minToMs         , hrToMs          , dayToMs         ,
    minToSec        , hrToSec         , dayToSec        , hrToMin         ,
    dayToMin        , dayToHr         , License         , Version         ,
    PUBLIC          , DateTime        , Duration        , Interval        ,
    Serial          , Column          , Primitive       , Finite          ,
    SmallInt        , Entries         , Indexed         , Key             ,
    Settings        , EntryType       , setEntryType    , now             ,
    $TriggerId      , $Id             , $Url            , $Path           ,
    $Email          , $Range          , escapeRegex     , tableToObjects  ,
    uno             , toCamelCase     , nonempty        , transpose       ,
    equivalent      , evalIndirect    , stringify       , minify          ,
    is              , type            , error           , assert          ,
    log             , partial         , retry           , profile         ,
    encode          , itoa            , atoi            , colNumToLet     ,
    id              , url             , user            ,
  });//return Object.assign exports
  //#endregion EXPORT
};//mrInit



///*<--EOF-->*///