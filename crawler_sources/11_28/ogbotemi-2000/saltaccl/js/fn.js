/* new, better algorithm for restruct */
let loop = function(str, props, from, to, cb, step) {
  ['from', 'to', 'step'].forEach(e=>props[e]=Math.abs(props[e]||0))
  from = props['from'], to = props['to'], step = props['step']||1, cb = props['cb'];
  if(typeof cb !== 'function') cb =_=>!!0;
  let result = [''], has=!0, reach = from+to, down = props['back'];
  
  for(; !cb(str, from, to, result)&&(to?from < reach:has);) {
    result[0] += (has=str[result[1] = down?from -=step:from +=step])||'';

    if(down&&to&&from===to) break;
  }
  if(down) result[0] = result[0].split('').reverse().join(''), result[1] &&= ++result[1];
  return result
},
/* i+=2 below because two characters - /* delimit the start of multi-line comments */
storeComments=(i, s, arr)=>(loop(s, {from:i+=2, cb:(s,f,t,r)=>s[f++]+s[f]==='*/'&&(i=f, arr.push('/*'+r[0]+'*/'), !0) }), i),
getStyleRule = (fr, s, slctr, exit)=>(slctr=[], loop(s, {from:fr, cb:to=>{

  if(s[fr--]==='}') { return exit = true; }
  else if(s[fr-1]+s[fr] === '*/') for(fr-=2; s[fr]+s[--fr] !=='*/'&&fr; );
  else {
    to = s[fr]||'';
    if(to) slctr.push(to.replace('}', '')), slctr[0]==='*'&&(slctr[0]+='/');
    else return true;
  }
}, back:true}), [slctr.reverse().join('').trim(), ++fr, exit]),
separateProperties=(res, in_bracket, arr=[], prop = '', incr=0)=>(loop(res, {from:0, cb:(_, _f)=>{
  prop +=_=res[_f]||'';
  if(_==='(' ) in_bracket=_;
  else if(_===')') in_bracket=false;
  
  if(!in_bracket&&prop) {
    if(_===';'||!res[_f]) arr[incr++]=prop, prop='';
  }
}}), arr);


function fn(str, input, callbacks, fast, result) {
  let base = {comments:[], indexes:[]};

  if(input&&(input=(input.__proto__===Array.prototype?input:[input]).filter(e=>e)).length) {
    let css='', once = 1, i = 0,
    len = str.length, self = fn, result = self.result ||= {}, rgx, end=id=>(input.forEach((e, res)=>{
      (res = result[e])&&(res.loopedThrough=!0);
      if(!res.matched.length) {
        delete res
      }
    }), clearInterval(id), /*cAF(id), restruct.index = i,*/ callbacks&&typeof callbacks['end']==='function'&&callbacks['end'](i, result, input), 0);

    for(let decr=input.length, j; decr--;) {
      j=input[decr], (result[j] ||= (self.index = i = 0, {matched:[], selectors:[], indexes:[]}));
      if(!(result[j]&&result[j].loopedThrough)) (rgx||=[]).push(j);
    }
    rgx &&= new RegExp('('+rgx.join('|')+')');
    for(let at_rule='', res='', sel_ind=0, sel_prop='', el; (once||(fast&&i<len))||fast&&end();) {
      if(!self.__loop) self.__loop = id => {
        if(!(i<len)) end(id);
        callbacks&&typeof callbacks['progress']==='function'&&callbacks['progress'](i, result, input);
        // setting once below to 0 prevents an infinite loop
        once = 0,
        el = str[i];
        /* prioritize comments by matching them first */
        if(el+str[i+1]==='/*') {
          //The returned value below is incremented to make i point to a character afer  '/' in the closing comment
          el = str[i = storeComments(i, str, base.comments)+1]
        }
        let curly_index;
        css +=el;
        if(el ==='@') loop(str, {from:i, cb:(s, f, t, r)=>{
          at_rule  = (at_rule +=t = s[f = i++]).replace('/*/', '');
          if(t+s[f+1]==='/*') i = storeComments(f, str, base.comments)-1;
          else if(/\{|;/.test(t)) return true
        }});
        else if(el==='}') getStyleRule(i-1, str)[2]&&(at_rule='');
        else if(el==='{') curly_index=i, loop(str, {from:++i, cb:(s, f)=>{

          /** the assignment below makes the loop continue from where comments stop */
            f = i++;
            if(s[f]+s[f+1]==='/*') i = storeComments(f, str, base.comments)-1;
            res = (res+=str[f]).replace('/*/', '');

            if('}'=== s[f+1]) {
              i = ++f,
              css+=res+'}';
              let styleRule = (at_rule&&at_rule+' ') + getStyleRule(curly_index, str)[0].replace(at_rule, '').trim(), sels, index=0;

              res.replace(rgx, (a,b,c, _res)=> {
                _res = result[sel_prop=a], sels = _res.selectors,
                _res.matched = _res.matched.concat(separateProperties(res).filter((e, _i)=>(e=rgx.test(e))&&++index  )), index&&[base, _res].forEach(arr=>arr.indexes.push(index));
                /\{/.test(sels[sel_ind-1]||'')
                ? !at_rule&&(sels[sel_ind-1]+= ' }')
                : at_rule&&(styleRule+=' {'),
                // console.log('MATCH::', _res, result)
                sel_ind = _res.selectors.push(styleRule)
              }),
              res = '';
              /** the return statement below ends this loop */
              return true;
            }
          }
        });
        /* the increment below is not to be modified otherwise inconsistencies will arise */
        let temp=result[sel_prop];
        temp &&=temp.selectors;
        temp&&i >= len-1 && /\{/.test(temp[sel_ind=temp.length-1])&&(temp[sel_ind]= temp[sel_ind].replace(/\{$/, '')+' }'),
        i = self.index++ // i = self.index++; //needed to make i not exceed j when boosting, by storing it globally
      };
      fast&&self.__loop(),
      !fast&&/*rAF*/(self.__loop, true)
    }
    // console.log(css)
  }
  return result
}

console.time();

let result = fn(str=`:root{--variable:value}
html {
  scroll-behaviour: smooth;
} 
.more {
  content-visibility: visible;more-properties:<considered>
} 
/**/@media/*parse error comment*/ (min-width: 500px) {
  [close]{
    visi/* void comment*/bility: hidden/*useful for making elements not focusable by the tab key*/
  }
  .opaque {
    opacity: 1
  }
  .c/*parse-breaking comment*/olor {color: auto; background:inherit;border-color: un/*some more comments please*/set;}
  hidden {
    display:none;
  }.bg-/*renders style block void*/unset{
    background-color: unset 
  }
}
@keyframes spin {
  50% {
    transform: rotate(180deg);
  }
  100% {
    transform: rotate(0deg);
  }
}
after-at-rule {
  css-lvl-1: value
}
.selector {
  <property>:<value>;
}.wireframe {
  background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAICAYAAAA4GpVBAAAAAXNSR0IArs4c6QAAABRJREFUGFdj+P///38GdOLgdnQxAHSiH1tWgHpMAAAAAElFTkSuQmCC);
  c/**/olor: black
}
`.trim().replace(/\n+|\t+/g, '').replace(/\s+/g, ' '), ['visi'], {}, true);
console.timeEnd()

console.log(fn.result)