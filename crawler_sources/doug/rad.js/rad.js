// Random Access Data
// How to store and access rows in a big datafile in javascript

var rad = (function(window, document, undefined) {

var defaults = {
  batch_size: 10000,  // number of items to batch fetch
  header_size: 2048  // bytes
};

function fetchMetadata(url, header_size, callback) {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', url, true);
  xhr.overrideMimeType('text\/plain; charset=x-user-defined');
  xhr.setRequestHeader('Range', 'bytes=0-' + (header_size - 1));
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
      var metasize = 0;
      for(var i=0;i<4;i++) {
        metasize += xhr.responseText.charCodeAt(i) >> (i*8);
      }
      console.log(metasize);
      var offset = metasize + 4;
      var metastr = xhr.responseText.substring(4, offset);
      var metadata = JSON.parse(metastr);
      // check to make sure metadata has: size, count, parser
      // if parser is url fetch the parser string first
      metadata.parser = eval(metadata.parser);
      metadata.header_size = offset;
      callback(metadata);
    }
  };
  xhr.send(null);
}

function extend(obj) {
  for (var i=1,l=arguments.length;i<l;i++) {
    var source = arguments[i];
    for (var prop in source) {
      obj[prop] = source[prop];
    }
  }
  return obj;
}

function File(url, metadata, opt_config) {
  var file = this;
  // TODO: extend as read-only attributes
  extend(file, defaults, opt_config, metadata);
  file.url = url;
  return file;
}

function fetch(file, start, end, onend, oneach, onstart) {
  start = file.header_size + start * file.size;
  end = Math.min(end, file.count);
  end = file.header_size + end * file.size - 1;
  var xhr = new XMLHttpRequest();
  xhr.open('GET', file.url, true);
  xhr.overrideMimeType('text\/plain; charset=x-user-defined');
  xhr.setRequestHeader('Range', 'bytes=' + start + '-' + end);
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
      if (onstart) {
        onstart();
      }
      // iterate through the responseText at file.size step and return array
      var items = [];
      for (var i=0,l=xhr.responseText.length/file.size; i<l; i++) {
        var item = file.parser(xhr.responseText.substring(i*file.size, (i+1)*file.size));
        if (oneach) {
          oneach(item);
        }
        if (onend) {
          items.push(item);
        }
      }
      if (onend) {
        onend(items);
      }
    }
  };
  xhr.send(null);
}

function after(counter, callback) {
  return function() {
    if (--counter <= 0) {
      if (callback) {
        callback();
      }
    }
  };
}

File.prototype.get = function(start, end, onend, oneach, onstart) {
  var file = this;
  switch (arguments.length) {
    case 2: // one item
      oneach = end;
      end = start+1;
      break;
    case 3: // item range
      break;
    case 4:
      break;
    case 5:
      break;
    default:
      if (console.error) {
        console.error('Incorect syntax, please see documention.');
      }
      return;
  }
  if (end - start < file.batch_size) {
    fetch(file, start, end, onend, oneach, onstart);
  } else {
    var resultsMap = {};
    var count = Math.ceil((end - start) / file.batch_size);
    var done;
    if (onend) {
      var _onend = onend;
      done = after(count, function() {
            // merge results and call onend 
            var results = [];
            for(var i=start; i<end; i+=file.batch_size) {
              results = results.concat(resultsMap[i]);
            }
            _onend(results);
          }); 
    }
    var i=start;
    if (onend) {
      onend = function(items) {
        resultsMap[i - file.batch_size] = items;
        done();
      }
    }
    var _onstart = onstart;
    onstart = function() {
      if (_onstart) {
        _onstart();
      }
      i += file.batch_size;
      if (i < end) {
        fetch(file, i, i + file.batch_size, onend, oneach, onstart);
      }
    }
    fetch(file, i, i + file.batch_size, onend, oneach, onstart);
  }
};

File.prototype.forEach = function(start, end, callback) {
  switch (arguments.length) {
    case 1:
    callback = start;
    start = 0;
    end = this.count;
    break;
    case 2:
    callback = end;
    end = this.count;
    break;
    default:
  }
  this.get(start, end, null, callback);
};

File.prototype.iter = function(start, end) {
  return new Iterator(this, start, end);
};

function Iterator(file, start, end) {
  var iter = this;
  iter.file = file;
  iter.start = start;
  iter.end = end;
  iter.index = 0;
  iter._batchIndex = 0;
  iter._futureCallbacks = {};
  iter._items = [];
  iter.batch_size = Math.min(file.batch_size, end-start);
  iter.count = end - start;
  batchFetch(iter);
  return iter;
}

// if the next get happens before this one then batchIndex is out of order
// issues where iter.file.get later returns before former
function batchFetch(iter) {
  var pos = iter._batchIndex;
  if (pos === iter.count) {
    return;  // return if at the end
  }
  var next = Math.min(pos + iter.batch_size, iter.count);
  iter._batchIndex += next-pos;
  var callback = true;
  var i = 0;
  iter.file.get(pos, next, null, function(item) {
    if (callback) {
      callback = iter._futureCallbacks[pos + i];
      if (callback) {
        callback(item);
        delete iter._futureCallbacks[pos + i];
        // setTimeout((function(callback, item, idx) {
        //   callback(item);
        //   delete iter._futureCallbacks[idx];
        // })(callback, item, pos + i), 0);
        i++;
        return;
      }
    }
    iter._items.push(item);
    i++;
  });
}

Iterator.prototype.has_next = function() {
  return this.index < this.count;
};

Iterator.prototype.next = function(callback) {
  var iter = this;
  if (iter.index >= iter.count) {
    callback(null);
  }
  var i = iter.index;
  iter.index += 1;
  if (Math.floor(i + iter.batch_size / 2) % iter.batch_size === 0) {
    batchFetch(iter);
  }
  var item = iter._items.shift();
  if (item) {
    callback(item);
  } else {
    iter._futureCallbacks[i] = callback;
  }
};


return {
  File: File,
  file: function(url, callback, opt_config) {
    opt_config = opt_config || {};
    fetchMetadata(url, opt_config.header_size || defaults.header_size,
      function(metadata) {
        var f = new File(url, metadata, opt_config);
        callback(f);
      }
    );
  }
};

})(window, document);
