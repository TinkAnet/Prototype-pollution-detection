module.exports = function(context) {
    const CONFIG_FILE = "minifyconfig.json";
    var deferral = require('q').defer();

    // Load modules
    var fs = require('fs');
    var path = require('path');
    var dependencyPath = path.join(process.cwd(), 'node_modules');
    const { minify } = require(path.join(dependencyPath, "terser"));
    var CleanCSS = require('clean-css');


    // configuration
    var configFile = path.join(context.opts.projectRoot, CONFIG_FILE);
    var fileConfig = {};
    if (fs.existsSync(configFile)) {
        fileConfig = JSON.parse(fs.readFileSync(configFile, "utf8"));
    }
    config = {
        minifyEnabled: "Release",
        combineJavascripts: {
            enabled: false,
            /* Experimental. May cause problems when javascriptStrategy 
             * scanDirectories since javascript files may depend on one another */
            file: 'all.min.js',
        },
        files: {
            paths: [''],
            recursive: true,
            //javascriptStrategy: 'scanHtml', 
            javascriptStrategy: 'scanDirectories'
        },
        terserOptions: {
            nameCache: {},
        },
        cleanCSSOptions: {

        }
    }
    deepMerge(config, fileConfig);

    // Check configuration
    if (!config.minifyEnabled || config.minifyEnabled == 'Never') {
        console.log("Minification disabled in config file.");
        return;
    } else if (config.minifyEnabled == 'Release') {
        if (!context.opts.options.release) {
            console.log("Not minifying, only enabled for --release builds.");
            return;
        }
    } else if (config.minifyEnabled !== true && config.minifyEnabled != 'Always') {
        console.warn("Not minifying, unknown minifyEnabled value specified in options, value was " +
            config.minifyEnabled + " expected one of the following 'Never, Always, Release'");
        return;
    }
    if (config.combineJavascripts.enabled &&
        config.files.javascriptStrategy != 'scanHtml') {
        console.warn("combineJavascripts.enabled may cause problems with" +
            " files.javascriptStrategy option if javascript files depend on one another");
    }
    console.log("Minify configuration: ");
    console.log(config);

    // Start minification process
    context.opts.paths.forEach(function(wwwpath) {
        run(wwwpath);
    });
    return deferral.promise;

    /**
     * Copies properties of source to target replacing existing properties.
     * If an property is an object call deepMerge recursively.
     */
    function deepMerge(target, source) {
        for (key in source) {
            if (typeof source[key] === 'object' &&
                typeof target[key] === 'object') {
                deepMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }

    /**
     * runs minifier for specified wwwpath
     */
    function run(wwwpath) {
        var javascriptFiles = [];
        var pending = config.files.paths.length;
        config.files.paths.forEach(function(file) {
            walkFiles(path.join(wwwpath, file), function(err, results) {
                if (err) {
                    console.log(err);
                }
                javascriptFiles = javascriptFiles.concat(results);
                if (!--pending) {
                    // remove duplicates
                    for (var i = 0; i < javascriptFiles.length; ++i) {
                        for (var j = i + 1; j < javascriptFiles.length; ++j) {
                            if (javascriptFiles[i] == javascriptFiles[j])
                                javascriptFiles.splice(j--, 1);
                        }
                    }

                    processJavascriptFiles(wwwpath, javascriptFiles);
                }
            });
        });
    }

    /** 
     * Walks files in specified path, gathers javascripts for later processing
     * and processes html and css files
     */
    function walkFiles(filepath, done) {
        fs.stat(filepath, function(err, stat) {
            if (err) {
                console.log("Skipping " + file + " Error: " + err);
                return done(err, null);
            }
            var results = [];
            if (stat.isDirectory()) {
                fs.readdir(filepath, function(err, list) {
                    var pending = list.length;
                    if (!pending) return done(null, results);
                    list.forEach(function(file) {
                        file = path.join(filepath, file);
                        walkFiles(file, function(err, res) {
                            results = results.concat(res);

                            if (!--pending) done(err, results);
                        });
                    })
                });
            } else if (stat.isFile()) {
                switch (path.extname(filepath)) {
                    case '.js':
                        if (config.files.javascriptStrategy == 'scanDirectories') results.push(filepath);
                        break;
                    case '.css':
                        processCSSFile(filepath);
                        break;
                    case '.html':
                        results = results.concat(processHtmlFile(filepath));
                        break;
                }
                done(null, results);
            }
        });
    }

    /**
     * Processes Html file
     * if config.files.javascriptStrategy == true returns referenced javascript files
     * if config.combineJavascripts.enabled == true replaces javascript references with minified file
     */
    function processHtmlFile(file) {

        var results = [];

        var html = fs.readFileSync(file, "utf8");
        var SRC_REGEX = /<script(?<before>[^>]*)src="(?<src>[^"]*)"(?<after>[^>]*)>/gi;

        // gather javascripts from html
        if (config.files.javascriptStrategy == 'scanHtml') {
            //console.log("scanning " + file);
            while ((match = SRC_REGEX.exec(html)) !== null) {
                console.log("script found: " + match.groups.src);
                results.push(path.join(path.dirname(file), match.groups.src));
            }
        }

        // replace for minified combined version
        if (config.combineJavascripts.enabled) {
            //console.log("editing " + file);
            // remove all src from javascript tags
            while (SRC_REGEX.test(html)) {
                var v = html.match(SRC_REGEX);
                html = html.replace(SRC_REGEX, "<script$<before>$<after>>");
            }

            // replace first empty script with minified combined javascript file, remove others
            var first = true;
            var SCRIPT_REGEX = /<script((?!src=)[^>])*><\/script>[\r\n\s]*/i;
            while (SCRIPT_REGEX.test(html)) {
                html = html.replace(SCRIPT_REGEX,
                    (first ? '<script src="' + config.combineJavascripts.file + '"></script>' : ''));
                first = false;
            }
            fs.writeFileSync(file, html);
        }
        return results;
    }

    function processCSSFile(file) {
        var result = new CleanCSS(config.cleanCSSOptions).minify(fs.readFileSync(file, "utf8"));
        fs.writeFileSync(file, result.styles);
    }

    /**
     * Minifies javascript files.
     * if config.combine.enabled combines files in one minified file (order based on array)
     */
    async function processJavascriptFiles(wwwpath, files) {
        var mapSource = config.terserOptions.sourceMap != undefined && config.terserOptions.sourceMap != false;
        var sourceMapDir = path.join(context.opts.projectRoot, "sourcemap/");
        var options = config.terserOptions;
        if (config.combineJavascripts.enabled) {
            console.log("combining and minifying " + files.length + " javascript files");
            var content = {};
            for (file of files) {
                console.log(file);
                content[file] = fs.readFileSync(file, "utf8");
                if (mapSource) {
                    console.log(path.join(sourceMapDir, 'sources', file.substring(wwwpath.length)));
                    fs.rename(file, path.join(sourceMapDir, 'sources', file.substring(wwwpath.length)), () => {});
                } else {
                    fs.unlink(file, () => {});
                }
            }
            var result = await minify(content, options);
            fs.writeFileSync(path.join(wwwpath, config.combineJavascripts.file), result.code);
            if (mapSource) {
                fs.writeFileSync(path.join(sourceMapDir, config.combineJavascripts.file + ".map"), result.map);
            }

            deferral.resolve();
        } else {
            pending = files.length;
            files.forEach(async function(file) {
                var result = await minify(fs.readFileSync(file, "utf8"), options);
                fs.writeFileSync(file, result.code);
                if (!--pending)
                    deferral.resolve();
            });
        }
    }
};