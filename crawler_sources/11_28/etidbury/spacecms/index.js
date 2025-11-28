/*eslint-disable */
SpaceCMSClient = function (onUpdate) {
    ///todo: write a modal window on browser to illustrate loading of livereload
    ///todo: add handler when injecting this library more than once. i.e. when user imports library in their react project
    var GLOBAL_VAR_NAME = "__spacecms_global";

    var API_PREFIX = "/api/v1/";

    var throwError = function (err) {
        console.error("CMS Live Reload Failure Occurred");
        console.trace("CMS Live Reload Error: ", err);
    };


    /*----extract host name----*/
    function extractHostname(url) {
        var hostname;
        //find & remove protocol (http, ftp, etc.) and get hostname

        if (url.indexOf("://") > -1) {
            hostname = url.split('/')[2];
        }
        else {
            hostname = url.split('/')[0];
        }

        //find & remove port number
        hostname = hostname.split(':')[0];
        //find & remove "?"
        hostname = hostname.split('?')[0];

        return hostname;
    }

    /*---/extract host name----*/

    try {

        /*------deepmerge----*/
        function isMergeableObject(val) {
            var nonNullObject = val && typeof val === 'object'

            return nonNullObject
                && Object.prototype.toString.call(val) !== '[object RegExp]'
                && Object.prototype.toString.call(val) !== '[object Date]'
        }

        function emptyTarget(val) {
            return Array.isArray(val) ? [] : {}
        }

        function cloneIfNecessary(value, optionsArgument) {
            var clone = optionsArgument && optionsArgument.clone === true
            return (clone && isMergeableObject(value)) ? deepmerge(emptyTarget(value), value, optionsArgument) : value
        }

        function defaultArrayMerge(target, source, optionsArgument) {
            var destination = target.slice()
            source.forEach(function (e, i) {
                if (typeof destination[i] === 'undefined') {
                    destination[i] = cloneIfNecessary(e, optionsArgument)
                } else if (isMergeableObject(e)) {
                    destination[i] = deepmerge(target[i], e, optionsArgument)
                } else if (target.indexOf(e) === -1) {
                    destination.push(cloneIfNecessary(e, optionsArgument))
                }
            })
            return destination
        }

        function mergeObject(target, source, optionsArgument) {
            var destination = {}
            if (isMergeableObject(target)) {
                Object.keys(target).forEach(function (key) {
                    destination[key] = cloneIfNecessary(target[key], optionsArgument)
                })
            }
            Object.keys(source).forEach(function (key) {
                if (!isMergeableObject(source[key]) || !target[key]) {
                    destination[key] = cloneIfNecessary(source[key], optionsArgument)
                } else {
                    destination[key] = deepmerge(target[key], source[key], optionsArgument)
                }
            })
            return destination
        }

        function deepmerge(target, source, optionsArgument) {
            var array = Array.isArray(source);
            var options = optionsArgument || {arrayMerge: defaultArrayMerge}
            var arrayMerge = options.arrayMerge || defaultArrayMerge

            if (array) {
                return Array.isArray(target) ? arrayMerge(target, source, optionsArgument) : cloneIfNecessary(source, optionsArgument)
            } else {
                return mergeObject(target, source, optionsArgument)
            }
        }

        deepmerge.all = function deepmergeAll(array, optionsArgument) {
            if (!Array.isArray(array) || array.length < 2) {
                throw new Error('first argument should be an array with at least two elements')
            }

            // we are sure there are at least 2 values, so it is safe to have no initial value
            return array.reduce(function (prev, next) {
                return deepmerge(prev, next, optionsArgument)
            })
        }
        /*------/deepmerge----*/


        //todo: transform to Promise format
        var loadScript = function (url, isAlreadyLoaded, callback) {
            if (isAlreadyLoaded) {
                callback();
                return;
            }

            var script = document.createElement("script");
            script.type = "text/javascript";

            if (script.readyState) { //IE
                script.onreadystatechange = function () {
                    if (script.readyState === "loaded" || script.readyState === "complete") {
                        script.onreadystatechange = null;
                        callback();
                    }
                };
            } else { //Others
                script.onload = function () {
                    callback();
                };
            }

            script.src = url;
            document.getElementsByTagName("head")[0].appendChild(script);
        };


        //todo: check correct versions have loaded for each library

        /*--show loading--*/


        loadScript('//ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js', typeof window.jQuery !== "undefined", function () {
            loadScript('//cdn.bootcss.com/twig.js/0.8.9/twig.js', typeof window.twig !== "undefined" && typeof window.twig === "function", function onLoadTwig() {
                loadScript('//cdnjs.cloudflare.com/ajax/libs/sails.io.js/1.1.10/sails.io.min.js', typeof window.io !== "undefined" && typeof window.io.sails !== "undefined", function onLoadSailsIo() {

                    var gn = GLOBAL_VAR_NAME;

                    if (!window[gn]) {
                        throwError("Global Variables not loaded");
                        return;
                    }


                    /*------quickfix: override configuration set by gulplite when using querystring------*/
                    //todo: improve and add better fix than current quickfix for setting configuration for staging env.

                    //if (window.location.host.indexOf(".firepit.tech") > -1) {


                    var getParameterByName = function (name, url) {
                        if (!url) url = window.location.href;
                        name = name.replace(/[\[\]]/g, "\\$&");
                        var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
                            results = regex.exec(url);
                        if (!results) return null;
                        if (!results[2]) return '';
                        return decodeURIComponent(results[2].replace(/\+/g, " "));
                    };


                    var stagingProjectName = getParameterByName('project');
                    //var stagingProjectName = /\/p\/(.*)\//.exec("http://staging.firepit.tech.dev/p/boilerplate/?gelll=hello#/")[1].replace(/\//g, '');


                    if (stagingProjectName && stagingProjectName !== null) {//if querystring is set
                        window[gn].project = {
                            name: stagingProjectName
                        };
                    }


                    var stagingAPIURL = getParameterByName('api_url');
                    //var stagingProjectName = /\/p\/(.*)\//.exec("http://staging.firepit.tech.dev/p/boilerplate/?gelll=hello#/")[1].replace(/\//g, '');

                    if (stagingAPIURL && stagingAPIURL !== null) {//if querystring is set

                        if (!window[gn].config)
                            window[gn].config = {};


                        window[gn].config.api_url = stagingAPIURL;


                        window[gn].project = {
                            name: stagingProjectName
                        };
                    }


                    //}


                    /*------/quickfix: override configuration set by gulplite when using querystring------*/


                    var API_URL = window[gn].config.api_url;


                    var hostName = extractHostname(API_URL);


                    if (hostName === "localhost") {
                        io.sails.url = "//" + extractHostname(API_URL) + ":4088/";
                    } else {
                        io.sails.url = "//" + extractHostname(API_URL);
                    }

                    io.connect(io.sails.url);


                    io.socket.on('disconnect',()=>{
                        //https://stackoverflow.com/questions/41400510/sails-socket-wont-reconnect
                        io.socket._raw.io._reconnection = true;
                    });


                    //var socket=io('http://localhost:4088');

                    var _spaceData = window[gn].space;
                    var _spaceUpdateCooldownTimeout;

                    jQuery(document).ready(function () {

                        var $body = jQuery(window.document.body);


                        var bodyTemplate = twig({
                            id: "body",
                            //href: "templates/posts.twig",
                            // for this example we'll block until the template is loaded
                            async: false
                            , data: $body.html()
                            // The default is to load asynchronously, and call the load function
                            //   when the template is loaded.
                            /*, load: function(template) {
                             console.log("embed-head-snippet.html:load (39)","loading tmp",template);//fordebug: debug print
                             }*/
                        });

                        var _previouslyRenderedSpaceData = {};

                        var _render = function () {

                            //var h = twig({ref: "body"}).render({space: _spaceData,md:Math.random()});

                            //console.log("_cms-livereload.js:_render (85)",h);//fordebug: debug print

                            _spaceData = Object.assign({}, _spaceData);

                            var h = bodyTemplate.render({space: _spaceData, md: Math.random()});

                            $body[0].innerHTML = h;

                            var $scripts = jQuery('script:not([async],[id])', $body).detach();//avoid browsersync injection and ext. libraries

                            window[gn].space = _spaceData;

                            window['_space'] = _spaceData;


                            console.log("index.js:render (105)", _spaceData);//fordebug: debug print

                            _previouslyRenderedSpaceData = _spaceData;


                            $scripts.appendTo($body);

                            window.dispatchEvent(new CustomEvent('spacecms:update', {detail: _spaceData}));

                            try {

                                window.document.getElementById("cms-loading-dialog").style.display = "none";

                            } catch (err) {
                                console.error("Failed to remove CMS loading dialog", err);//fordebug: print debug
                            }

                            if (typeof onUpdate === "function")
                                onUpdate(_spaceData);

                        };

                        var mapSpacesArrayToAssoc = function (spacesArray) {
                            var m = {};

                            spacesArray.forEach(function (space) {

                                m[space.uri_label] = Object.assign({}, space.formData);

                            });

                            return m;
                        };

                        //$body.html('Loading Dev Environment...');


                        io.socket.on('connect',function(){



                            jQuery.ajax({
                                method: 'GET',
                                url: API_URL + 'project/' + window[gn].project.name + '/spaces'
                            }).then(function (spaces)
                            {

                                /*Object.keys(spaces).forEach(function(spaceURILabel){
                                    io.socket.get(API_PREFIX + 'space/' + spaceURILabel + '/subscribe');
                                });*/

                                _spaceData = spaces;

                                return true;

                            }).then(function () {



                                /*io.socket.on('space', function onSpaceUpdate(Space) {


                                    clearTimeout(_spaceUpdateCooldownTimeout);
                                    _spaceUpdateCooldownTimeout = setTimeout(function () {
                                        _spaceData[Space.data[0].uri_label] = Object.assign(_spaceData[Space.data[0].uri_label] || {}, Space.data[0].formData);
                                        _render();
                                    }, window[gn].config.space_update_cooldown || 0);

                                });*/

                                io.socket.on('/project/'+window[gn].project.name +'/space/form/update',function(obj){
                                    console.log("index.js[344]:",obj);//fordebug: print debug
                                    clearTimeout(_spaceUpdateCooldownTimeout);

                                    _spaceUpdateCooldownTimeout = setTimeout(function () {
                                        _spaceData[obj.uri_label] = Object.assign(_spaceData[obj.uri_label]  || {}, obj.formData);
                                        _render();
                                    }, window[gn].config.space_update_cooldown || 0);
                                });

                               /* //return _render();
                                return jQuery.ajax({
                                    method: 'GET',
                                    url: API_URL + 'project/' + window[gn].project.name + '/spaces'
                                });*/
                                _render();

                            });

                        });
                        //todo: add error handling

                    });


                });//end jQuery.ready

            });//end load io.sails

        });//end load twig


        /*-/show loading--*/


    } catch (err) {
        throwError(err);
    }


};

if (typeof exports === "undefined") {
    exports = this;
    SpaceCMSClient();
} else {
    exports = SpaceCMSClient;
}
/*eslint-enable */

