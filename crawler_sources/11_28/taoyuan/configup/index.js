const debug = require('debug')('configup');
const path = require('path');
const fs = require('fs');
const Module = require('module');
const assert = require('assert');
const json5 = require('json5');

const FILE_EXTENSION_JSON = '.json';
const JOSN_EXTS = ['.json', '.json5'];

module.exports = {
  load,
  findScripts,
  resolveRelativePaths,
  resolveAppScriptPath
};


/**
 *
 * @param {String} rootDir
 * @param {String} name
 * @param {Object|String|Boolean} [options]
 * @param {String} [options.env]
 * @param {String} [options.merge]
 * @returns {*}
 */
function load(rootDir, name, options) {
  if (typeof options === 'string') {
    options = {env: options};
  } else if (typeof options === 'function') {
    options = {merge: options}
  }
  options = options || {};
  // const mergeFn = options.deepMerge ? deepMergeConfig(options.strict) : mergeConfig();
  return loadNamed(rootDir, name, options.env, mergeConfig());
}

/**
 * Load named configuration.
 * @param {String} rootDir Directory where to look for files.
 * @param {String} name
 * @param {String|Function} [env] Environment, usually `process.env.NODE_ENV`
 * @param {function(target:Object, config:Object, filename:String)} [mergeFn]
 * @returns {Object}
 */
function loadNamed(rootDir, name, env, mergeFn) {
  if (typeof env === 'function') {
    mergeFn = env;
    env = undefined;
  }
  mergeFn = mergeFn || mergeConfig();
  const files = findConfigFiles(rootDir, name, env);
  if (files.length) {
    debug('found %s %s files', env, name);
    files.forEach(function(f) { debug('  %s', f); });
  }
  const configs = loadConfigFiles(files);
  const merged = mergeConfigurations(configs, mergeFn);

  debug('merged %s %s configuration %j', env, name, merged);

  return merged;
}

/**
 * Search `appRootDir` for all files containing configuration for `name`.
 * @param {String} appRootDir
 * @param {String} name
 * @param {String} [env] Environment, usually `process.env.NODE_ENV`
 * @returns {Array.<String>} Array of absolute file paths.
 */
function findConfigFiles(appRootDir, name, env) {
  let master = ifExists(name + '.json');
  if (!master) {
    master = ifExists(name + '.json5');
  }
  if (!master && (ifExistsWithAnyExt(name + '.local') ||
    ifExistsWithAnyExt(name + '.' + env))) {
    console.warn('WARNING: Main config file "%s.json" is missing', name);
  }
  if (!master) return [];

  const candidates = [
    master,
    ifExistsWithAnyExt(name + '.local'),
  ];

  if (env) {
    candidates.push(ifExistsWithAnyExt(name + '.' + env));
  }

  candidates.push(ifExistsWithAnyExt(name + '.overrides'));

  return candidates.filter(function(c) { return c !== undefined; });

  function ifExists(fileName) {
    const filepath = path.resolve(appRootDir, fileName);
    return fs.existsSync(filepath) ? filepath : undefined;
  }

  function ifExistsWithAnyExt(fileName) {
    return ifExists(fileName + '.js') || ifExists(fileName + '.json') || ifExists(fileName + '.json5');
  }
}

/**
 * Load configuration files into an array of objects.
 * Attach non-enumerable `_filename` property to each object.
 * @param {Array.<String>} files
 * @returns {Array.<Object>}
 */
function loadConfigFiles(files) {
  return files.map(function (f) {
    const config = JOSN_EXTS.includes(path.extname(f)) ? json5.parse(fs.readFileSync(f)) : require(f);
    Object.defineProperty(config, '_filename', {
      enumerable: false,
      value: f,
    });
    debug('loaded config file %s: %j', f, config);
    return config;
  });
}

/**
 * Merge multiple configuration objects into a single one.
 * @param {Array.<Object>} configObjects
 * @param {function(target:Object, config:Object, filename:String)} mergeFn
 */
function mergeConfigurations(configObjects, mergeFn) {
  const result = configObjects.shift() || {};
  while (configObjects.length) {
    const next = configObjects.shift();
    mergeFn(result, next, next._filename);
  }
  return result;
}

function mergeConfig() {
  return (target, config, fileName) => {
    const err = mergeObjects(target, config);
    if (err) {
      throw new Error(`Cannot apply ${fileName}: ${err}`);
    }
  };
}

function deepMergeConfig(strict) {
  function deepMerge(target, config, filename) {
    const err = mergeObjects(target, config);
    if (err) {
      throw new Error('Cannot apply ' + filename + ': ' + err);
    }
  }

  return (target, config, filename) => {
    if (!target) return;

    if (strict) {
      for (const key in target) {
        if (typeof target[key] === 'object') {
          deepMerge(target[key], config[key], filename);
        } else {
          target[key] = config[key];
        }
      }
    } else {
      deepMerge(target, config, filename);
    }
  }
}

function mergeObjects(target, config, keyPrefix) {
  for (const key in config) {
    const fullKey = keyPrefix ? keyPrefix + '.' + key : key;
    const err = mergeSingleItemOrProperty(target, config, key, fullKey);
    if (err) return err;
  }
  return null; // no error
}

function mergeSingleItemOrProperty(target, config, key, fullKey) {
  const origValue = target[key];
  const newValue = config[key];

  if (!hasCompatibleType(origValue, newValue)) {
    return 'Cannot merge values of incompatible types for the option `' +
      fullKey + '`.';
  }

  if (Array.isArray(origValue)) {
    return mergeArrays(origValue, newValue, fullKey);
  }

  if (newValue !== null && typeof origValue === 'object') {
    return mergeObjects(origValue, newValue, fullKey);
  }

  target[key] = newValue;
  return null; // no error
}

function mergeArrays(target, config, keyPrefix) {
  if (target.length !== config.length) {
    return 'Cannot merge array values of different length' +
      ' for the option `' + keyPrefix + '`.';
  }

  // Use for(;;) to iterate over undefined items, for(in) would skip them.
  for (let ix = 0; ix < target.length; ix++) {
    const fullKey = keyPrefix + '[' + ix + ']';
    const err = mergeSingleItemOrProperty(target, config, ix, fullKey);
    if (err) return err;
  }

  return null; // no error
}

function hasCompatibleType(origValue, newValue) {
  if (origValue === null || origValue === undefined)
    return true;

  if (Array.isArray(origValue))
    return Array.isArray(newValue);

  if (typeof origValue === 'object')
    return typeof newValue === 'object';

  // Note: typeof Array() is 'object' too,
  // we don't need to explicitly check array types
  return typeof newValue !== 'object';
}

/*--  --*/

/**
 * Find all javascript files (except for those prefixed with _)
 * and all directories.
 * @param {String} dir Full path of the directory to enumerate.
 * @return {Array.<String>} A list of absolute paths to pass to `require()`.
 * @private
 */
function findScripts(dir/*, extensions*/) {
  assert(dir, 'cannot require directory contents without directory name');

  const files = tryReadDir(dir);
  //extensions = extensions || _.keys(require.extensions);

  // sort files in lowercase alpha for linux
  files.sort(function (a, b) {
    a = a.toLowerCase();
    b = b.toLowerCase();

    if (a < b) {
      return -1;
    } else if (b < a) {
      return 1;
    } else {
      return 0;
    }
  });

  const results = [];
  files.forEach(function (filename) {
    // ignore index.js and files prefixed with underscore
    if (filename === 'index.js' || filename[0] === '_') {
      return;
    }

    const filepath = path.resolve(path.join(dir, filename));
    const stats = fs.statSync(filepath);

    // only require files supported by require.extensions (.txt .md etc.)
    if (stats.isFile()) {
      if (isPreferredExtension(filename))
        results.push(filepath);
      else
        debug('Skipping file %s - unknown extension', filepath);
    } else {
      debug('Skipping directory %s', filepath);
    }
  });

  return results;
}

function tryReadDir() {
  try {
    return fs.readdirSync.apply(fs, arguments);
  } catch (e) {
    return [];
  }
}

function resolveAppPath(rootDir, relativePath, resolveOptions) {
  const resolvedPath = tryResolveAppPath(rootDir, relativePath, resolveOptions);
  if (resolvedPath === undefined && !resolveOptions.optional) {
    const err = new Error('Cannot resolve path "' + relativePath + '"');
    err.code = 'PATH_NOT_FOUND';
    throw err;
  }
  return resolvedPath;
}

function tryResolveAppPath(rootDir, relativePath, resolveOptions) {
  let fullPath;
  const start = relativePath.substring(0, 2);

  /* In order to retain backward compatibility, we need to support
   * two ways how to treat values that are not relative nor absolute
   * path (e.g. `relativePath = 'foobar'`)
   *  - `resolveOptions.strict = true` searches in `node_modules` only
   *  - `resolveOptions.strict = false` attempts to resolve the value
   *     as a relative path first before searching `node_modules`
   */
  resolveOptions = resolveOptions || {strict: true};

  let isModuleRelative = false;
  if (relativePath[0] === '/') {
    fullPath = relativePath;
  } else if (start === './' || start === '..') {
    fullPath = path.resolve(rootDir, relativePath);
  } else if (!resolveOptions.strict) {
    isModuleRelative = true;
    fullPath = path.resolve(rootDir, relativePath);
  }

  if (fullPath) {
    // This check is needed to support paths pointing to a directory
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }

    try {
      fullPath = require.resolve(fullPath);
      return fullPath;
    } catch (err) {
      if (!isModuleRelative) {
        debug('Skipping %s - %s', fullPath, err);
        return undefined;
      }
    }
  }

  // Handle module-relative path, e.g. `loopback/common/models`

  // Module.globalPaths is a list of globally configured paths like
  //   [ env.NODE_PATH values, $HOME/.node_modules, etc. ]
  // Module._nodeModulePaths(rootDir) returns a list of paths like
  //   [ rootDir/node_modules, rootDir/../node_modules, etc. ]
  const modulePaths = Module.globalPaths
    .concat(Module._nodeModulePaths(rootDir));

  fullPath = modulePaths
    .map(function (candidateDir) {
      const absPath = path.join(candidateDir, relativePath);
      try {
        // NOTE(bajtos) We need to create a proper String object here,
        // otherwise we can't attach additional properties to it
        /*jshint -W053 */
        const filePath = String(require.resolve(absPath));
        filePath.unresolvedPath = absPath;
        return filePath;
      } catch (err) {
        return absPath;
      }
    })
    .filter(function (candidate) {
      return fs.existsSync(candidate.toString());
    })
    [0];

  if (fullPath) {
    if (fullPath.unresolvedPath && resolveOptions.fullResolve === false)
      return fullPath.unresolvedPath;
    // Convert String object back to plain string primitive
    return fullPath.toString();
  }

  debug('Skipping %s - module not found', relativePath);
  return undefined;
}

function resolveRelativePaths(relativePaths, appRootDir) {
  const resolveOpts = {strict: false};
  relativePaths.forEach(function (relativePath, k) {
    const resolvedPath = tryResolveAppPath(appRootDir, relativePath, resolveOpts);
    if (resolvedPath !== undefined) {
      relativePaths[k] = resolvedPath;
    } else {
      debug('skipping boot script %s - unknown file', relativePath);
    }
  });
}

function getExcludedExtensions() {
  return {
    '.json': '.json',
    '.node': 'node'
  };
}

function isPreferredExtension(filename) {
  const includeExtensions = require.extensions;

  const ext = path.extname(filename);
  return (ext in includeExtensions) && !(ext in getExcludedExtensions());
}

function fixFileExtension(filepath, files, onlyScriptsExportingFunction) {
  const results = [];
  let otherFile;

  /* Prefer coffee scripts over json */
  if (isPreferredExtension(filepath)) return filepath;

  const basename = path.basename(filepath, FILE_EXTENSION_JSON);
  const sourceDir = path.dirname(filepath);

  files.forEach(function (f) {
    otherFile = path.resolve(sourceDir, f);

    const stats = fs.statSync(otherFile);
    if (stats.isFile()) {
      const otherFileExtension = path.extname(f);

      if (!(otherFileExtension in getExcludedExtensions()) &&
        path.basename(f, otherFileExtension) === basename) {
        if (!onlyScriptsExportingFunction)
          results.push(otherFile);
        else if (onlyScriptsExportingFunction &&
          (typeof require.extensions[otherFileExtension]) === 'function') {
          results.push(otherFile);
        }
      }
    }
  });
  return (results.length > 0 ? results[0] : undefined);
}

function resolveAppScriptPath(rootDir, relativePath, resolveOptions) {
  const resolvedPath = resolveAppPath(rootDir, relativePath, resolveOptions);
  if (!resolvedPath) {
    return false;
  }
  const sourceDir = path.dirname(resolvedPath);
  const files = tryReadDir(sourceDir);
  const fixedFile = fixFileExtension(resolvedPath, files, false);
  return (fixedFile === undefined ? resolvedPath : fixedFile);
}
