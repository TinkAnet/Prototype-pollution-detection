const compoent_name_prefix = "compoent_name_";
const translate_component_key = "translation_";
const id_key = "id_";

//swiping matrix/////Hector on Jul 28 2024////////////////
class swipingMatrix {
  cells = [];
  constructor({ parent, matrix, events }) {
    this.id = generateRandomString(10);
    this.wrapper = document.createElement('div');
    this.wrapper.style.position = "relative";
    this.wrapper.style.width = "100%";
    this.wrapper.style.height = "100%";
    this.wrapper.style.overflow = "hidden";

    this.container = document.createElement('div');
    this.container.style.position = "absolute";
    this.container.style.top = 0;
    this.container.style.left = 0;
    this.container.style.width = "300%";
    this.container.style.height = "300%";
    this.container.style.display = "flex";
    this.container.style.flexWrap = "wrap";
    this.container.addEventListener('touchstart', this.touchStart.bind(this));
    this.container.addEventListener('touchmove', this.touchMove.bind(this));
    this.container.addEventListener('touchend', this.touchEnd.bind(this));
    this.wrapper.append(this.container);
    this.createDomCell();

    //init variable
    this.matrix = matrix;
    this.touchstartX = 0;
    this.touchstartY = 0;
    this.isSwiping = false;
    this.containerInitialX = 0;
    this.containerInitialY = 0;
    this.directionLocked = null;
    this.transformDuration = 0.3;
    this.eventList = {
      "endSwipe": (action) => { },
    }
    for (let key in events) {
      this.eventList[key] = events[key].bind(this);
    }

    //set parent
    this.parent = parent;
    this.parent.style.margin = 0;
    this.parent.style.padding = 0;
    this.parent.style.overflow = "hidden";
    this.parent.style.height = "100%";
    this.parent.style.width = "100%";
    this.parent.append(this.wrapper);
    this.renderMatrix();
  }
  createDomCell() {
    for (let i = -1; i <= 1; i++) {
      const tmpRow = [];
      for (let j = -1; j <= 1; j++) {
        const row = i + 1;
        const col = j + 1;
        const cell = document.createElement('div');
        cell.style.flex = "0 0 33.33%";
        cell.style.height = "33.33%";
        cell.style.width = "33.33%";
        cell.style.display = "flex";
        cell.style.alignItems = "center";
        cell.style.justifyContent = "center";
        cell.style.boxSizing = "border - box";
        cell.classList.add('swipe_panel_cell');
        this.container.appendChild(cell);
        tmpRow.push(cell);
      }
      this.cells.push(tmpRow);
    }
  }

  updateMatrix(matrix) {
    console.log(matrix)
    this.matrix = matrix;
    this.renderMatrix();
  }
  renderMatrix() {
    for (let i = -1; i <= 1; i++) {
      for (let j = -1; j <= 1; j++) {
        const row = i + 1;
        const col = j + 1;
        const cell = this.cells[row][col];

        switch (typeof this.matrix[row][col]) {
          case "string":
            cell.innerHTML = this.matrix[row][col];
            break;
          case "function":
            this.matrix[row][col](resp => {
              if (resp === null) {
                //maybe here should be call request data again. aug 6 2024 hector
                return
              }
              const { html } = resp;
              let content = `<div class='swipe_cell'>${html}</div>`;
              cell.innerHTML = content;
              this.matrix[row][col] = content;
            });
            break;
          default:
            cell.innerHTML = this.matrix[row][col];
        }
      }
    }
    // 暂时移除过渡效果
    this.container.style.transition = 'none';
    // 设置目标位置
    this.container.style.transform = `translate(-33.33%, -33.33%)`;
    // 强制重绘以应用无过渡的样式变化
    this.container.offsetHeight; // 读取属性触发重绘
    // 恢复过渡效果
    this.container.style.transition = '';
  }

  touchStart(e) {
    this.touchstartX = e.changedTouches[0].screenX;
    this.touchstartY = e.changedTouches[0].screenY;
    this.isSwiping = true;
    this.container.style.transition = 'none';
    this.directionLocked = null;
    const style = window.getComputedStyle(this.container);
    const matrix = new WebKitCSSMatrix(style.transform);
    this.containerInitialX = matrix.m41;
    this.containerInitialY = matrix.m42;
  }
  touchMove(e) {
    if (!this.isSwiping) return;
    const touch = e.changedTouches[0];
    const diffX = touch.screenX - this.touchstartX;
    const diffY = touch.screenY - this.touchstartY;

    if (this.directionLocked === null) {
      this.directionLocked = Math.abs(diffX) > Math.abs(diffY) ? 'horizontal' : 'vertical';
    }

    if (this.directionLocked === 'horizontal') {
      this.container.style.transform = `translate(${this.containerInitialX + diffX}px, ${this.containerInitialY}px)`;
    } else if (this.directionLocked === 'vertical') {
      this.container.style.transform = `translate(${this.containerInitialX}px, ${this.containerInitialY + diffY}px)`;
    }
  }

  touchEnd(e) {
    if (!this.isSwiping) return;
    this.isSwiping = false;

    const touchendX = e.changedTouches[0].screenX;
    const touchendY = e.changedTouches[0].screenY;
    const diffX = touchendX - this.touchstartX;
    const diffY = touchendY - this.touchstartY;
    let moveDirection = undefined;

    if (this.directionLocked === 'horizontal') {
      if (Math.abs(diffX) > window.innerWidth / 6) {
        if (diffX > 0) {
          this.container.style.transform = `translate(0%, -33.33%)`;
          moveDirection = "left";
        } else {
          this.container.style.transform = `translate(-66.66%, -33.33%)`;
          moveDirection = "right";
        }
      }
    } else if (this.directionLocked === 'vertical') {
      if (Math.abs(diffY) > window.innerHeight / 6) {
        if (diffY > 0) {
          this.container.style.transform = `translate(-33.33%, 0%)`;
          moveDirection = "down";
        } else {
          this.container.style.transform = `translate(-33.33%, -66.66%)`;
          moveDirection = "up";
        }
      }
    }

    this.container.style.transition = `transform ${this.transformDuration}s ease`;
    if (moveDirection) {
      //continue the move
      setTimeout(() => {
        this.renderMatrix();
        //trigger touch end event callback

      }, this.transformDuration * 1000 * 0.5);
    } else {
      //reset the position
      this.container.style.transform = `translate(-33.33%, -33.33%)`;
    }
    if (this.eventList['endSwipe']) this.eventList['endSwipe'](moveDirection);
  }

  updateEvent(name, fn) {
    if (typeof fn === "function") this.eventList[name] = fn;
  }
}

//matrix navigator // hecor on Aug 3 2024////////////////
class matrixNavigator {
  inputMatrix = null;
  currentRow = 0;
  currtneCol = 0;
  outputSize = 3;
  boarderCell = "<h1>this is boarder</h1>"
  loadingCell = "<h1>Loading</h1>"
  //////////////////////////////////
  constructor({ inputMatrix, indexedDB, lc, initRow = 0, initCol = 0 }) {
    this.inputMatrix = inputMatrix;
    this.currentRow = initRow;
    this.currtneCol = initCol;
    this.indexedDB = indexedDB;
  }
  getContentFromDataSource(hash, callback) {
    this.indexedDB.getDataWithCallback(hash, callback);
  }
  getContentFromPos({ row, col }) {
    try {
      //mean the boarder
      if (row === -1) return this.boarderCell;
      switch (col) {
        case 0: {
          //means the cover col
          const hash = Object.keys(this.inputMatrix)[row];
          return (callback) => {
            this.getContentFromDataSource(hash, callback);
          };
        }
        case -1: {
          //mean the boarder
          return this.boarderCell;
        }
      }
      const matrix = Object.values(this.inputMatrix);
      const [similarity, hash] = matrix[row][col - 1];
      if (!hash) throw `hash in getContentFromPos error: ${hash}`;
      return (callback) => { this.getContentFromDataSource(hash, callback) };
    } catch (error) {
      console.error(row, col, error);
      return this.loadingCell;
    }
  }

  moveZero() {
    console.log(this.currentRow, this.currtneCol);
    const ret = [];
    for (let rowIdx = 0; rowIdx < this.outputSize; rowIdx++) {
      const rowArr = [];
      for (let colIdx = 0; colIdx < this.outputSize; colIdx++) {
        const row = this.currentRow - 1 + rowIdx;
        const col = this.currtneCol - 1 + colIdx;
        rowArr.push(this.getContentFromPos({ row, col }));
      }
      ret.push(rowArr);
    }
    return ret;
  }

  moveUp() {
    if (this.currentRow >= Object.keys(this.inputMatrix).length - 1) return this.moveZero();
    this.currentRow += 1;
    //reset column when change row, mean change subjest
    this.currtneCol = 0;
    return this.moveZero();
  }

  moveDown() {
    try {
      if (this.currentRow === 0) return this.moveZero();

      this.currentRow--;
      //reset column when change row, mean change subjest
      this.currtneCol = 0;
      return this.moveZero();
    } catch (error) {
      return this.moveZero();
    }
  }

  moveRight() {
    try {
      const row = Object.values(this.inputMatrix)[this.currentRow];
      if (this.currtneCol < row.length - 1) this.currtneCol++;
      return this.moveZero();
    } catch (error) {
      return this.moveZero();
    }
  }

  moveLeft() {
    try {
      if (this.currtneCol > 0) this.currtneCol--;
      return this.moveZero();
    } catch (error) {
      return this.moveZero();
    }
  }

  updateMatrix(matrix) {
    this.inputMatrix = matrix;
  }

}
//////////////////////////////////////////////////////
class UserEvent {
  constructor(type, category, action, label, value) {
    this.timestamp = new Date().toISOString();
    this.type = type;
    this.category = category;
    this.action = action;
    this.label = label;
    this.value = value;
    // this.sessionId = getSessionId(); // 实现这个函数来获取会话ID
    // this.userId = getUserId(); // 实现这个函数来获取用户ID
    this.pageUrl = window.location.href;
    this.userAgent = navigator.userAgent;
  }
}

class UserActivityTracker {
  constructor() {
    this.events = [];
    this.pageViewStartTime = new Date();
    this.currentPageUrl = window.location.href;
  }

  trackEvent(type, category, action, label = null, value = null) {
    const event = new UserEvent(type, category, action, label, value);
    this.events.push(event);
  }

  trackPageView() {
    // 如果这不是首次加载，先记录上一个页面的停留时间
    if (this.pageViewStartTime) {
      this.trackPageDuration();
    }

    // 记录新的页面访问
    this.pageViewStartTime = new Date();
    this.currentPageUrl = window.location.href;
    this.trackEvent('pageview', 'engagement', 'view', window.location.pathname);
  }

  trackPageDuration() {
    const endTime = new Date();
    const duration = (endTime - this.pageViewStartTime) / 1000; // 转换为秒
    this.trackEvent('pageduration', 'engagement', 'time_on_page', this.currentPageUrl, duration);
  }

  // sendEvents() {
  //   // 在发送事件之前，先记录当前页面的停留时间
  //   this.trackPageDuration();

  //   if (this.events.length === 0) return;

  //   fetch('/api/user-activities', {
  //     method: 'POST',
  //     headers: {
  //       'Content-Type': 'application/json',
  //     },
  //     body: JSON.stringify(this.events)
  //   })
  //     .then(response => response.json())
  //     .then(data => {
  //       console.log('Events sent successfully:', data);
  //       this.events = []; // 清空已发送的事件
  //     })
  //     .catch(error => console.error('Error sending events:', error));
  // }
}

////////////////////////
class elementRootH {
  elementList = {};
  routes = {};
  currentRoute = "";
  constructor() {
    this.tracker = new UserActivityTracker()
    this.attachToPost = this.tracker.events;
  }

  setRoute(path, fn) {
    //从子路径中改变父路径的元素属性，必须由子元素调用父元素函数
    /* this.routes 的结构例子
    {
      "mainPanel": {
        "@": { "params": {},"next": {} },
        "game.index": {
          "@": { "params": {}, "next": {} }
        },
        "news.index": {
          "@": { "params": {}, "next": {} },
          "kkk": { "@": { "params": {}, "next": {} }
          }
        }
      }
    }
    */
    const route = {};
    let currentPath = route;
    const { subPaths, params } = this.url_hash_spliter(path);
    for (let pathStep of subPaths) {
      currentPath[pathStep] = {
        "@": {
          params,
          next: {}
        }
      }
      switch (pathStep) {
        case "@": {
          console.warn("path '@' not allow.");
          return;
        }
        case subPaths[subPaths.length - 1]: {
          //if reach last element 
          currentPath[pathStep]['@']['function'] = fn.bind(this);
          break;
        }
      }
      currentPath = currentPath[pathStep];
    }
    this.routes = deepMerge(this.routes, route);
  }
  goRoute(path) {
    this.releaseResource(path);
    if (path === this.currentRoute) return;
    this.currentRoute = path;
    let currentPath = this.routes;
    const { subPaths, params } = this.url_hash_spliter(path);
    for (let pathStep of subPaths) {
      if (currentPath[pathStep] === undefined) {
        console.error(`${path} not found.`);
      }
      checkAndRun(currentPath[pathStep], params);
      currentPath = currentPath[pathStep];
    }
    window.location.hash = window.location.hash.charAt(0) !== '#' ? `#${path}` : `${path}`;

    this.tracker.trackPageView();
    ///////////////////////////
    function checkAndRun(fn, param) {
      if (fn['@']['function']) if (typeof (fn['@']['function']) === "function") {
        return fn['@']['function'](param);
      }
      return false;
    }
  }
  releaseResource(newRoute) {
    ///////////////////////////
    const findDiffPath = (routeOne, routeTwo) => {
      const { subPaths: targetPath } = this.url_hash_spliter(routeOne);
      const { subPaths: currentPath } = this.url_hash_spliter(routeTwo);
      for (let idx = 0; idx < currentPath.length; idx++) {
        if (currentPath[idx] !== targetPath[idx]) return currentPath[idx];
      }
      return false;
    }
    ////////////////////////////////
    const diffPath = findDiffPath(newRoute, this.currentRoute);
    if (diffPath) this.del(diffPath);
  }
  add(name, ele) {
    if (!this.has(name)) this.elementList[name] = ele;
  }
  del(name) {
    if (this.has(name)) {
      const deleteList = this.elementList[name].DOM.querySelectorAll(`[${compoent_name_prefix}]`);
      for (let el of deleteList) {
        const eleName = el.getAttribute(compoent_name_prefix);
        if (this.has(eleName)) {
          this.elementList[eleName].destory();
          delete this.elementList[eleName];
        }
      }
      this.elementList[name].destory();
      delete this.elementList[name];
    }
  }
  get(name) {
    if (this.has(name)) {
      return this.elementList[name];
    } else {
      return undefined;
    }
  }
  has(name) {
    return this.elementList[name] !== undefined;
  }

  url_hash_spliter(queryString) {
    if (!queryString) return { subPaths: {}, params: {} };
    const [path, params] = queryString.replace(/#/g, "").split("?");
    const paramsObj = {};
    if (Array.isArray(params)) for (let param of params.split("&")) {
      const [key, value] = param.split("=");
      paramsObj[key] = value;
    }
    const pathObj = [];
    for (let target of path.split("/")) {
      //如果target为空，为null, 或为false会跳过
      if (!target) continue;
      pathObj.push(target);
    }
    return { subPaths: pathObj, params: paramsObj }
  }
}
const elementRoot = new elementRootH();

//////////////////////////////////////////////////////
class variable {
  updateList = {};
  data = null;

  constructor(defaultVal = undefined) {
    this.data = defaultVal;
  }

  get() {
    return this.data;
  }

  set(data) {
    const previousData = this.data;
    this.data = data;

    //update compoents
    for (let key in this.updateList) {
      const { component, renderHandle } = this.updateList[key];
      if (component && component.renders && component.renders[renderHandle] !== undefined) {
        component.renders[renderHandle](data);
      } else {
        delete this.updateList[key];
      }
    }
    return previousData;
  }
  onChangeCall(component, renderHandle) {
    this.updateList[Object.values(this.updateList).length] = { component, renderHandle };
  }
}

//////Hector on Jun 1////////////////
class baseComponent {
  elements = {};
  renders = {};

  constructor({ name, structure, parent, render, events, variable, script, fromElementId }) {
    if (elementRoot.has(name)) {
      console.warn(`component name ${name} already existed.`);
      return elementRoot.get(name);
    }
    elementRoot.add(name, this);
    this.name = name;
    this.parent = parent;
    //html
    if (fromElementId !== undefined) {
      this.DOM = document.querySelector("#" + fromElementId)
    } else {
      this.processStructure(structure);
    }

    //variable
    for (let key in variable) {
      if (!Object.hasOwnProperty(key)) {
        this[key] = variable[key];
      }
    }
    //render
    for (let itm in render) {
      this.renders[itm] = render[itm].bind(this);
    }
    //event
    if (Array.isArray(events)) for (let { target, event, fn } of events) {

      if (this.elements[target] && typeof fn === "function") {
        this.elements[target].addEventListener(event, fn.bind(this));
      }
    }
    //script
    this.script = [];
    if (script) for (let itm of script) {
      this.script.push(loadScript(itm));
    }
  }

  render(obj) {
    for (let itm in obj) {
      if (this.renders[itm]) this.renders[itm](obj[itm]);
    }
  }

  processStructure(structure) {
    const parser = new DOMParser();
    const dom = parser.parseFromString(structure, "text/html");
    this.DOM = dom.body.firstElementChild;
    const elements = dom.querySelectorAll(`[${id_key}]`);
    try {
      this.parent.append(this.DOM);
      this.DOM.setAttribute(compoent_name_prefix, this.name);
      for (let el of elements) {
        this.elements[el.getAttribute(`${id_key}`)] = el;
      }
    } catch (error) {
      console.error(error, `name = ${this.name}, parent = ${this.parent}`);
    }
  }

  destory() {
    for (let itm in this.renders) this.renders[itm] = null;

    const descendants = document.querySelectorAll(`[${compoent_name_prefix}]`);
    for (let el of descendants) {
      // elementRoot[el.getAttribute(compoent_name_prefix)].destory();
    }
    for (let itm in this.script) unloadScript(itm);
    this.renders = null;
    this.DOM.remove();
  }
}


//通用函数//////////////////////////////////////////////////
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;

  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }

  return result;
}

function deepMerge(target, source) {
  if (typeof target !== 'object' || target === null) {
    return source;
  }

  if (typeof source !== 'object' || source === null) {
    return target;
  }

  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) {
          target[key] = Array.isArray(source[key]) ? [] : {};
        }
        target[key] = deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }

  return target;
}

function handleSwipe({ touchstartX, touchstartY, touchendX, touchendY }, swipeArea) {
  if (!isTouchDevice()) return;
  const diffX = touchendX - touchstartX;
  const diffY = touchendY - touchstartY;

  if (Math.abs(diffX) > Math.abs(diffY)) {
    // Horizontal swipe
    if (diffX > 0) {
      console.log('Swiped right');
      swipeArea.textContent = 'Swiped Right';
    } else {
      console.log('Swiped left');
      swipeArea.textContent = 'Swiped Left';
    }
  } else {
    // Vertical swipe
    if (diffY > 0) {
      console.log('Swiped down');
      swipeArea.textContent = 'Swiped Down';
    } else {
      console.log('Swiped up');
      swipeArea.textContent = 'Swiped Up';
    }
  }
}

function getAncestors(element, attribute = compoent_name_prefix) {
  let ancestors = [];
  while (element) {
    ancestors.push(element);
    if (element.getAttribute(attribute) !== undefined) {
      break;
    }
    element = element.parentElement;
  }
  return ancestors;
}
function getDescendants(element, conditionFn) {
  let descendants = [];

  function traverse(node) {
    let children = node.children;
    for (let i = 0; i < children.length; i++) {
      if (typeof conditionFn === "function") {
        if (conditionFn(children[i])) {
          descendants.push(children[i]);
        }
      }
      traverse(children[i]);
    }
  }

  traverse(element);
  return descendants;
}
//动态加载js
function loadScript(url, callback) {
  const script = document.createElement('script');
  script.src = url;
  script.type = 'text/javascript';
  script.onload = function () {
    if (callback) callback();
  };
  document.head.appendChild(script);
  return script;
}

// 卸载 JavaScript 文件
function unloadScript(scriptElement) {
  if (scriptElement && scriptElement.parentNode) {
    scriptElement.parentNode.removeChild(scriptElement);
  }
}
//动态加载css
async function loadStyles(stylesheets, parent = document.head) {
  if (parent === undefined) return false;
  let arr = await Promise.all(stylesheets.map(url => fetch(url)));
  arr = await Promise.all(arr.map(url => url.text()));
  const style = document.createElement('style');
  style.textContent = arr.reduce(
    (prev, fileContents) => prev + fileContents, ''
  )
  parent.appendChild(style);
}
//
function throttle(fn, wait) {
  let lastCall = Date.now() - wait;
  return function () {
    let now = Date.now();
    if (now - lastCall >= wait) {
      lastCall = now;
      fn.apply(this, arguments);
    }
  };
}

/////非阻塞渲染间任务
function _runTask(task, callback) {
  let start = Date.now();
  requestAnimationFrame(() => {
    if (Date.now() - start < 16.6) {
      task();
      callback();
    } else {
      _runTask(task, callback);
    }
  })
}
function isTouchDevice() {
  return 'ontouchstart' in window || navigator.maxTouchPoints > 0 || navigator.msMaxTouchPoints > 0;
}
//////////测试是否touchable device
window.onload = function () {
  const infoDiv = document.getElementById('body');

  if (isTouchDevice()) {
    console.log("This device is touch-enabled.");
  } else {
    console.log("This device is using a mouse or other non-touch input.");
  }
};
var isMobile = /iPhone|iPod|iPad|Android|BlackBerry/.test(navigator.userAgent);
function vibrate() {
  if (isMobile) {
    navigator.vibrate(50);
  }
}
//////////
export default {
  baseComponent,
  variable,
  UserActivityTracker,
  swipingMatrix,
  matrixNavigator,
  id_key,
  throttle,
  handleSwipe,
  elementRoot,
  translate_component_key,
  loadScript,
  unloadScript
}

///////
class LinkedListQueue {
  constructor() {
    this.front = null;
    this.rear = null;
    this.size = 0;
  }

  enqueueFront(element) {
    const newNode = new Node(element);
    if (this.isEmpty()) {
      this.front = this.rear = newNode;
    } else {
      newNode.next = this.front;
      this.front.previous = newNode;
      this.front = newNode;
    }
    this.size++;
  }

  dequeueRear() {
    if (this.isEmpty()) return null;

    const removedElement = this.rear.element;
    if (this.front === this.rear) {
      this.front = this.rear = null;
    } else {
      this.rear = this.rear.previous;
      if (this.rear) {
        this.rear.next = null;
      } else {
        this.front = null;
      }
    }
    this.size--;
    return removedElement;
  }

  isEmpty() {
    return this.size === 0;
  }

  getSize() {
    return this.size;
  }

  frontElement() {
    return this.isEmpty() ? null : this.front.element;
  }

  rearElement() {
    return this.isEmpty() ? null : this.rear.element;
  }
}
