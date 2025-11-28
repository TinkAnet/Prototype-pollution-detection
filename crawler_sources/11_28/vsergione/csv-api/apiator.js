apiatorDebug = false;
(function ($) {
    /**
     * 
     * @param opts
     * @returns {$|void}
     */
    $.fn.apiator = function (opts)
    {
        if(!this.length) {
            if(apiatorDebug) console.log("Warning: no DOM element bound with apiator",this);
        }

        if(typeof opts==="string") {
            opts = {
                url: opts,
            }
        }

        // extract data attributes from html element and assign them to
        let options = Object.assign({dataBindings: {},addontop:false}, this.data());

        // assign options passed as
        try {
            Object.assign(options, parseOptions(opts));
        }
        catch (e) {
            throw ["Error on Apiator init",e];
        }



        if (this.data("instance") !== undefined) {
            let instance = this.data("instance");

            if(options.url) {
                instance.setUrl(options.url);
                delete options.url;
            }

            Object.assign(instance,parseOptions(options));

            return options.returninstance ? instance : this;
        }

        if(apiatorDebug) console.log("init apiator on ",this,options);

        if(options.hasOwnProperty("emptyview")) {
            options.emptyview = $(options.emptyview).remove();
        }

        // resource type unknown
        if (!options.hasOwnProperty("resourcetype")) {
            options.resourcetype = "collection";
            if(apiatorDebug) console.log("WARNING: no resourcetype specified. Assumed it's a collection");
        }
        let listeners = options.on;
        delete options.on;

        console.log("options",options);


        let instance;
        switch ( options.resourcetype) {
            case "collection":
                instance = createCollectionInstance.bind(this)(this,options);
                break;
            case "item":
                instance = createItemInstance.bind(this)(this,options);
                break;
            default:
                throw new Error("Invalid resource type for APIATOR.JS (should be item or collection)." +
                    " Please define a valid resource on element "+this.attr("id"));
        }

        if(listeners) {
            Object.getOwnPropertyNames(listeners).forEach((eventName)=>{
                instance.on(eventName,listeners[eventName]);
            });
        }


        this.data("instance",instance);

        console.log("instance",instance.url);

        if(instance.url && (typeof instance.dontload==="undefined" || !instance.dontload)) {
            instance.loadFromRemote()
        }

        return (options.hasOwnProperty("returninstance") && opts.returninstance) ? instance : this;
    };


    $.fn.apiator.templateSettings = {
        evaluate: /<%([\s\S]+?)%>/g,
        interpolate: /<%=([\s\S]+?)%>/g,
        escape: /<%-([\s\S]+?)%>/g
    };
    $.fn.apiator.baseUrl = null;
    function _$1(obj) {
        if (obj instanceof _$1) return obj;
        if (!(this instanceof _$1)) return new _$1(obj);
        this._wrapped = obj;
    }
    function template(text, newSettings={}) {


        var noMatch = /(.)^/;
        function escapeChar(match) {
            return '\\' + escapes[match];
        }

        let settings = Object.assign({}, $.fn.apiator.templateSettings);
        Object.assign(settings, newSettings);

        // Combine delimiters into one regular expression via alternation.
        var matcher = RegExp([
            (settings.escape || noMatch).source,
            (settings.interpolate || noMatch).source,
            (settings.evaluate || noMatch).source
        ].join('|') + '|$', 'g');

        // Compile the template source, escaping string literals appropriately.
        var index = 0;
        var source = "__p+='";
        text.replace(matcher, function(match, escape, interpolate, evaluate, offset) {
            source += text.slice(index, offset).replace(escapeRegExp, escapeChar);
            index = offset + match.length;

            if (escape) {
            source += "'+\n((__t=(" + escape + "))==null?'':_.escape(__t))+\n'";
            } else if (interpolate) {
            source += "'+\n((__t=(" + interpolate + "))==null?'':__t)+\n'";
            } else if (evaluate) {
            source += "';\n" + evaluate + "\n__p+='";
            }

            // Adobe VMs need the match returned to produce the correct offset.
            return match;
        });
        source += "';\n";

        var argument = settings.variable;
        if (argument) {
            // Insure against third-party code injection. (CVE-2021-23358)
            if (!bareIdentifier.test(argument)) throw new Error(
            'variable is not a bare identifier: ' + argument
            );
        } else {
            // If a variable is not specified, place data values in local scope.
            source = 'with(obj||{}){\n' + source + '}\n';
            argument = 'obj';
        }

        source = "var __t,__p='',__j=Array.prototype.join," +
            "print=function(){__p+=__j.call(arguments,'');};\n" +
            source + 'return __p;\n';

        var render;
        try {
            render = new Function(argument, '_', source);
        } catch (e) {
            console.log("Error creating template function",source);
            console.log(text);
            e.source = source;
            throw e;
        }

        var template = function(data) {
            return render.call(this, data, _$1);
        };

        // Provide the compiled source as a convenience for precompilation.
        template.source = 'function(' + argument + '){\n' + source + '}';

        return template;
    }


    let overlay = $("<div>").text("Se incarca").addClass("komponent-overlay").attr("style","background: silver; text-align: center;position:absolute; z-index:100000");
    ()=>{
        function template_engine(template,varStart="{{",varStop="}}",xprStart="{(",xprStop=")}") {
            var tpl = template.replaceAll(varStart,"' + ((_t=( ").replaceAll(varStop," ))==null ? '' : _t) ");
            tpl = "function(obj) { var _p,_t; _p = '"+ tpl + "'";
            //tpl = tpl.replaceAll(xprStart,"';\n").replaceAll(varStop,";_p += '");

            return function(data) {
                this.template = tpl;
                with(data) {
                    return eval(tpl+"(data  )");
                }
            }
        }
        let test = '<ul>    <li><i class="fa fa-trash"></i>{{item1}}</li>    <li>{{item2}}</li>    <li>{{item3}}{(console.log(item3)}</li></ul>';
    };


    function dbg() {
        if(typeof apiatorDebug!=="undefined" && apiatorDebug)
            console.log(...arguments,arguments.callee.caller);
    }
    var escapes = {
        "'": "'",
        '\\': '\\',
        '\r': 'r',
        '\n': 'n',
        '\u2028': 'u2028',
        '\u2029': 'u2029'
    };

    var escapeRegExp = /\\|'|\r|\n|\u2028|\u2029/g;



// JavaScript micro-templating, similar to John Resig's implementation.
// Underscore templating handles arbitrary delimiters, preserves whitespace,
// and correctly escapes quotes within interpolated code.
// NB: `oldSettings` only exists for backwards compatibility.


    let itemsArr = {};
    let db = {};

    const EDIT_BUTTON_ACTION = "showEditModal";
    const ADD_BUTTON_ACTION = "showCreateModal";
    const DELETE_BUTTON_ACTION = "showDeleteConfirm";
    const NULL_ENTRY_VALUE = "/__null_entry__/";

    /**
     *
     * @param data
     * @param db (db)
     */
    function parseItemData(data,db)
    {
        let obj = {};
        let jsonApiObj = data.data;


        // retrieve self URLfse
        if(data.hasOwnProperty("links") && data.links && data.links.hasOwnProperty("self"))
            obj.url = URL(data.links.self);

        // fill info
        let jsonApiItem = data.hasOwnProperty("data")?data.data:data;
        let tmp = db.__get(jsonApiItem);
        if(tmp===null)
            tmp = {};
        obj = deepmerge(obj,tmp);

        // no relationships => job done & return
        if(!obj.relationships)
            return obj;

        // iterate relationships data and create Item Objects

        Object.getOwnPropertyNames(obj.relationships).forEach(function (relName) {
            // empty 1:1 relation
            if(obj.relationships[relName]===null)
                return;

            let relUrl = null;
            if(jsonApiObj.relationships[relName].hasOwnProperty("links")
                && jsonApiObj.relationships[relName].links.hasOwnProperty("related"))
                relUrl = jsonApiObj.relationships[relName].links.related;

            let relData = obj.relationships[relName];




            // 1:1 relation
            if(obj.relationships[relName].constructor===Object) {
                let opts = {
                    url: relUrl
                };
                obj.relationships[relName] = Item(opts).loadFromData(obj.relationships[relName]);
            }


            // 1:n relationship
            if(obj.relationships[relName].constructor===Array)
                obj.relationships[relName].map(function (itm) {
                    let found = db.__get(itm);

                    if(found)
                        return Item({url: relUrl}).loadFromData(itm);
                    else
                        return Item({url: relUrl}).loadFromData(found);
                });
        });

        return obj;
    }

    function deepmerge(target, source, optionsArgument)
    {
        function defaultArrayMerge(target, source, optionsArgument) {
            let destination = target.slice();
            source.forEach(function(e, i) {
                if (typeof destination[i] === 'undefined') {
                    destination[i] = cloneIfNecessary(e, optionsArgument);
                } else if (isMergeableObject(e)) {
                    destination[i] = deepmerge(target[i], e, optionsArgument);
                } else if (target.indexOf(e) === -1) {
                    destination.push(cloneIfNecessary(e, optionsArgument));
                }
            });
            return destination
        }

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
            let clone = optionsArgument && optionsArgument.clone === true;
            return (clone && isMergeableObject(value)) ? deepmerge(emptyTarget(value), value, optionsArgument) : value
        }


        function mergeObject(target, source, optionsArgument) {
            let destination = {};

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
            });
            return destination
        }

        let array = Array.isArray(source);
        let options = optionsArgument || { arrayMerge: defaultArrayMerge };
        let arrayMerge = options.arrayMerge || defaultArrayMerge;

        if (array) {
            return Array.isArray(target) ? arrayMerge(target, source, optionsArgument) : cloneIfNecessary(source, optionsArgument);
        } else {
            return mergeObject(target, source, optionsArgument);
        }
    }

    deepmerge.all = function deepmergeAll(array, optionsArgument)
    {
        if (!Array.isArray(array) || array.length < 2) {
            throw new Error('first argument should be an array with at least two elements');
        }

        // we are sure there are at least 2 values, so it is safe to have no initial value
        return array.reduce(function(prev, next) {
            return deepmerge(prev, next, optionsArgument);
        })
    };


    /**
     *
     * @param options
     * @returns {{}|*}
     */
    function parseOptions(options)
    {
        if(typeof options==="undefined") {
            return {};
        }

        if(options.constructor===Object) {
            return options;
        }

        throw ["Invalid apiator options",options];
    }

    /**
     *
     * @param doc
     */
    function flattenDoc(doc)
    {
        let arr = [];
        if(doc.hasOwnProperty("data") && doc.data!==null) {
            if(doc.data.constructor===Array)
                arr = doc.data;
            else
                arr.push(doc.data)
        }
        if(doc.hasOwnProperty("includes"))
            arr = arr.concat(doc.includes);

        arr.forEach(function (item) {
            if(!itemsArr.hasOwnProperty(item.type+"/"+item.id))
                itemsArr[item.type+"/"+item.id] = item;
        });
        return arr;
    }

    /**
     *
     * @param data
     * @returns {{__get: __get, __add: __add}}
     */
    function buildDb(data)
    {
        let db = {
            __get: function (resName,keyId) {
                if(!resName)
                    return  null;

                if(resName.constructor===Object && resName.hasOwnProperty("id") && resName.hasOwnProperty("type")) {
                    keyId = resName.id;
                    resName = resName.type
                }

                if(!this.hasOwnProperty(resName))
                    return null;

                if(!this[resName].hasOwnProperty(keyId))
                    return  null;

                return this[resName][keyId];
            },
            __add: function (resName,keyId,data) {
                if(!resName)
                    return  null;

                if(resName.constructor===Object && resName.hasOwnProperty("id") && resName.hasOwnProperty("type")) {
                    keyId = resName.id;
                    resName = resName.type
                    if(resName.hasOwnProperty("data"))
                        data = resName.data;
                }

                if(!this.hasOwnProperty(resName))
                    this[resName] = {};

                if(!this[resName].hasOwnProperty(keyId))
                    this[resName][keyId] = {
                        id: keyId,
                        type: resName
                    };

                if(data)
                    this[resName][keyId] = data;

                return this[resName][keyId];
            }
        };

        if(data.hasOwnProperty("data")) {
            db = deepmerge(db, parseDataProperty(data.data));
        }

        if(data.hasOwnProperty("includes")) {
            db = deepmerge(db, parseIncludesProperty(data.includes));
        }


        /**
         * fix relations
         */
        Object.getOwnPropertyNames(db).forEach(function (resName) {
            Object.getOwnPropertyNames(db[resName]).forEach(function (keyId) {
                if(!db[resName][keyId])
                    return;

                if(!db[resName][keyId].hasOwnProperty("relationships"))
                    return;

                Object.getOwnPropertyNames(db[resName][keyId].relationships).forEach(function (relName) {
                    if(!db[resName][keyId].relationships[relName].hasOwnProperty("data") || !db[resName][keyId].relationships[relName].data) {
                        db[resName][keyId].relationships[relName] = null;
                        return;
                    }


                    let relTmp = db[resName][keyId].relationships[relName].data;

                    if(relTmp.constructor===Object) {
                        let tmp = db.__get(relTmp);
                        if(!tmp)
                            tmp = db.__add(relTmp);
                        db[resName][keyId].relationships[relName] = tmp;
                    }

                    if(relTmp.constructor===Array) {
                        db[resName][keyId].relationships[relName] = [];
                        for(let i=0;i<relTmp.length;i++) {

                            let tmp = db.__get(relTmp[i].type,relTmp[i].id);
                            db[resName][keyId].relationships[relName].push(tmp?tmp:relTmp[i]);
                        }
                    }

                })
            });
        });

        /**
         *
         * @param data
         */
        function parseDataProperty(data)
        {
            let db = {};
            if(!data)
                return db;

            if(data.constructor===Object)
                data = [data];

            if(data.constructor!==Array)
                return db;

            return addItems2Db(data);
        }

        /**
         *
         * @param data
         */
        function parseIncludesProperty(data)
        {
            let db = {};
            if(!data || data.constructor!==Array)
                return db;

            return addItems2Db(data);

        }

        /**
         *
         * @param items
         */
        function addItems2Db(items)
        {
            let db = {};
            items.forEach(function (item) {
                if(!item.hasOwnProperty("attributes") && !item.hasOwnProperty("relationships"))
                    return;
                if(!db.hasOwnProperty(item.type))
                    db[item.type] = {};
                db[item.type][item.id] = item;
            });
            return db;
        }
        return db;
    }



    /**
     *
     * @param options
     * @returns {{relationships: null, view: null, attributes: null, id: null, collection: null, type: null, url: null}}
     */
    function Item(options)
    {
        // console.log("Item",options);
        let _item = {
            id: null,
            type: null,
            attributes: {},
            relationships: {},
            views: [],
            collection: null,
            url: null,
            updateUrl: null,
            deleteUrl: null,
            strict: false
        };

        const callbacks = {};

        _item.on = function(eventName,cb) {
            if(typeof callbacks[eventName]==="undefined") {
                callbacks[eventName] = [];
            }
            callbacks[eventName].push(cb);
            return _item;
        };

        try {
            Object.assign(_item,parseOptions(options));
        }
        catch (e) {
            throw ["Error on Item init",e];
        }
        
        let storage = options.ajaxOpts? Storage(options.ajaxOpts) : (options.collection && options.collection.ajaxOpts ? Storage(options.collection.ajaxOpts ) : Storage());

        _item.setUrl = function (url) {
            if(url.constructor===String) {
                this.url = URL(url);
                this.updateUrl = Object.assign({},this.url);
                this.deleteUrl = Object.assign({},this.url);
            }


            if(url.hasOwnProperty("url"))
                this.url = URL(url.url);
            if(url.hasOwnProperty("updateUrl"))
                this.updateUrl = URL(url.updateUrl);
            if(url.hasOwnProperty("deleteUrl"))
                this.deleteUrl = URL(url.deleteUrl);
            return this;
        };

        _item.url = URL(_item.url);
        _item.deleteUrl = URL(_item.deleteUrl?_item.deleteUrl:_item.url);
        _item.updateUrl = URL(_item.updateUrl?_item.updateUrl:_item.url);


        _item.views.forEach(function (view) {
            view.item = _item;
        });


        /**
         *
         * @param jqXHR
         * @param textStatus
         * @param errorThrown
         * @param _self
         */
        function fail(jqXHR, textStatus, errorThrown) {
            if(jqXHR.status===404) {
                // _self.view.renderEmpty();
                _item.views.forEach(function (view) {
                    view.renderEmpty();
                });
            }
        }

        /**
         * alias for load_from_data_source
         * @returns {Promise<unknown>}
         */
        _item.loadFromRemote = function() {
            return _item.load_from_data_source();
        };

        _item.refresh = _item.loadFromRemote;

        _item.reload = _item.loadFromRemote;


        /**
         * load item data from data source storage.
         * @returns {Promise<unknown>}
         */
        _item.load_from_data_source = function () {
            let loaders = [];
            _item.views.forEach((itemView)=> {
                loaders.push(overlay.clone().insertBefore(itemView.el)
                    .width($(itemView.el).width())
                    .height($(itemView.el).height()));
            });

            return new Promise(function (resolve,reject) {
                if(!_item.url) {
                    throw("No valid URL provided");
                }

                storage.read(_item,_item.url,{})
                    .then(function (resp) {
                        let data = resp.data;
                        _item
                            .loadFromJSONAPIDoc(data)
                            .render();
                        loaders.map((loader)=>loader.remove());
                        resolve(_item);
                    })
                    .catch(function(jqXHR, textStatus, errorThrown)
                    {
                        if(apiatorDebug) console.log("fail to load item resource",_item.url,jqXHR, textStatus, errorThrown);
                        fail(jqXHR, textStatus, errorThrown);
                        reject(jqXHR);
                    });

            });
        };

        _item.unbindView = function(view)
        {
            let found = false;
            for(let i=0;i<this.views.length;i++) {
                if(this.views[i]===view) {
                    found = i
                }
            }
            if(found!==false) {
                this.views.splice(found,1)
            }

        };


        /**
         *
         * @param view
         */
        _item.bindView = function(view,returnView) {
            if(!$(view).length) {
                throw "Nothing to bind to: empty view element";
            }

            view = ItemView(view);

            let bound = false;
            _item.views.forEach(function (v) {
                if(apiatorDebug) console.log("bind to existing view",v.el);
                if(v===view) {
                    bound = true;
                }
            });

            if(bound) {
                return;
            }
            view.item = _item;
            _item.views.push(view);
            if(returnView)
                return view;
            return this;
        };

        /**
         * method is used when loading item from remote (either not part of a collection)
         * @param data
         * @param text
         * @param xhr
         * @param ctx
         * @returns {_item}
         */
        _item.loadFromJSONAPIDoc = function (data) {
            if(apiatorDebug) console.log("Load from JSONAPIDoc",data);

            if(data.data && data.data.constructor===Array) {
                if(apiatorDebug) console.log("Invalid configuration: resource type is item but server response is collection",data);
                throw "Invalid configuration: resource type is item but server response is collection";
            }

            Object.assign(_item,parseItemData(data,buildDb(data)));
            _item.url = URL(_item.url);
            return _item;
        };


        _item.loadFromData = function (data) {
            // throw "Asa";
            let obj;

            if(this.hasOwnProperty("collection"))
                obj = this;

            else if(ctx && ctx.hasOwnProperty("collection"))
                obj = ctx;

            Object.assign(obj,data);

            return this;
        };


        /**
         * loads data statically from data parameter
         * @param data
         * @param text
         * @param xhr
         * @param ctx
         * @returns {_item}
         */
        _item.loadFromData = function (data) {
            // console.log("item load from data 2",_item.loadFromData.caller,data);

            if( data===null || typeof data!=="object" || data.constructor!==Object ) {
                console.log("cannot load ",data, " into ",_item);
                return _item;
            }

            // normalize data if not delivered in standard JSONAPI structure
            if(!data.hasOwnProperty("attributes") && !data.hasOwnProperty("id") && !data.hasOwnProperty("type") ) {
                console.log("need to normalize data",data);

                let attributes = {};

                let relationships = {};
                Object.getOwnPropertyNames(data).forEach(function (propName) {
                    if(data[propName] && data[propName].constructor===Object) {
                        relationships[propName] = Item().loadFromData(data[propName]);
                        delete attributes[propName];
                        return;
                    }
                    if(data[propName] && data[propName].constructor===Array) {
                        relationships[propName] = Collection().loadFromData(data[propName]);
                        delete attributes[propName];
                        return;
                    }

                    attributes[propName] = data[propName];
                });

                data = {
                    attributes: attributes,
                };

                if(Object.getOwnPropertyNames(relationships).length) {
                    data.relationships = relationships;
                }
            }


            Object.assign(_item,data);
            // console.log(_item);
            return _item;
        };


        /**
         *
         * @param xhr
         * @param statusText
         * @param error
         */
        _item.fail = function (xhr,statusText,error) {
            if(apiatorDebug) console.log("item.fail",xhr,statusText,error);
            // this.view.renderEmpty();
            this.view.forEach(function (view) {
                view.renderEmpty();
            });
        };


        /**
         *
         * @returns {{attributes: _item.attributes, type: _item.type}}
         */
        _item.toJSON = function () {
            let json = {
                type: this.type,
                attributes: this.attributes
            };
            if (this.id)
                json.id = this.id;
            if (this.attributes)
                json.attributes = this.attributes;

            if (!this.hasOwnProperty("relationships"))
                return json;

            json.relationships = {};

            for (let relName in this.relationships) {
                if (!this.relationships.hasOwnProperty(relName))
                    continue;

                json.relationships[relName] = {
                    data: null,
                };

                if (this.relationships[relName] === null)
                    continue;

                // 1:1 relation
                if (this.relationships[relName].constructor === Object) {
                    json.relationships[relName].data = this.relationships[relName].hasOwnProperty("toJSON")
                        ? this.relationships[relName].toJSON() : this.relationships[relName];
                    continue;
                }

                // invalid relation data (not null, not an object, not an array)
                if (this.relationships[relName].constructor !== Array) {
                    delete this.relationships[relName];
                    delete json.relationships[relName];
                    continue;
                }

                // 1:n relations
                json.relationships[relName].data = [];
                for (let i = 0; i < this.relationships[relName].length; i++) {
                    let tmp = this.relationships[relName][i].hasOwnProperty("toJSON")
                        ? this.relationships[relName][i].toJSON()
                        : this.relationships[relName][i];
                    json.relationships[relName].data.push(tmp);
                }
            }
            if(apiatorDebug) console.log("item.json",json);
            return json;
        };

        _item.sync = function() {
            if(_item.syncOp) {
                let syncOp = _item.syncOp;
                console.log("Syncing",_item,syncOp);
                _item.syncOp = null;
                return syncOp();
            }
            else {
                console.log("Nothing to sync on",_item)
            }
        };

        function perform_update(opts) {
            // console.log("Perform update on ",_item);
            let options = {
                rerender: true
            };
            Object.assign(options,opts);

            return new Promise(function (resolve,reject) {
                let toUpdate = {
                    id: _item.id,
                    attributes: {},
                    relationships: {}
                };

                if(_item.type) {
                    toUpdate.type = _item.type;
                }
                Object.getOwnPropertyNames(_item.attributes).forEach(function (attrName) {
                    toUpdate.attributes[attrName] = _item.attributes[attrName];
                    return;
                    if(_item.shadow.attributes[attrName]!==_item.attributes[attrName]) {
                        toUpdate.attributes[attrName] = _item.attributes[attrName];
                    }
                });

                Object.getOwnPropertyNames(_item.relationships).forEach(function (relaName) {
                    toUpdate.relationships[relaName] = _item.relationships[relaName];
                    return;
                    if(_item.shadow.relationships[relaName]!==_item.relationships[relaName]) {
                        toUpdate.relationships[relaName] = _item.relationships[relaName];
                    } 
                });

                // nothing to update
                if(!Object.getOwnPropertyNames(toUpdate.attributes).length
                    && !Object.getOwnPropertyNames(toUpdate.relationships).length) {
                    _item.syncOp = null;
                    resolve(_item);
                }

                let patchData = JSON.stringify({data: toUpdate});

                // console.log("Send update data",_item,toUpdate,patchData);

                if(opts && opts.justSimulate) {
                    console.log(patchData);
                    resolve(_item);
                    return;
                }
                storage.update(_item,_item.updateUrl, {},patchData)
                    .then(function (resp)
                    {
                        // console.log("Update response received with fresh data",resp,options,opts);
                        let newData = parseItemData(resp.data,buildDb(resp.data));
                        Object.assign(_item,newData);
                        _item.shadow = null;

                        if(options.rerender) {
                            _item.views.forEach(function (view){
                                view.render();
                            });
                        }
                        if(callbacks.update) {
                            callbacks.update.forEach((cb)=>new Promise(()=>cb(_item)));
                        }

                        if(_item.collection) {
                            _item.collection.onupdate()
                        }
                        resolve(_item);
                    })
                    .catch(function (xhr)
                    {
                        if(apiatorDebug) console.log("Update NOK",_item.updateUrl,patchData,xhr);
                        reject(xhr);
                    });
            });
        }




        /**
         * Update item
         */
        _item.update = function (updateData,opts) {
            // console.log("Update",_item," with data",updateData);

            if(!updateData || updateData.constructor!==Object) {
                return ;
            }
            //check_pending_sync(perform_update);

            let updateOptions = {
                sync: true,
                rerender: true,
            };

            if(opts && opts.constructor===Object) {
                Object.assign(updateOptions, opts);
            }

            if(!_item.shadow) {
                _item.shadow = {attributes:{},relationships:{}};
                Object.assign(_item.shadow.attributes,_item.attributes);
                Object.assign(_item.shadow.relationships,_item.relationships);
            }

            /**
             *
             * @param rel
             * @param data
             * @returns {*}
             */
            function updateRelation(rel,data) {
                console.log("update relatin",rel,data)
                // console.log("Update relation",rel,data);

                // rel is 1:n
                if (rel && rel.hasOwnProperty("length")) {
                    // todo: fix this
                    console.log("to fix");
                    return rel;
                    if (data.constructor===Array || data.hasOwnProperty("items") ) {
                        // console.log("Update 1:n relation");
                        rel = {data:Collection().loadFromData(data)};
                    }
                    return rel;
                }

                // rel is 1:1
                if(typeof data==="object") {
                    console.log("Update 1:1 relation");
                    let item = Item().loadFromData(data);
                    console.log("relation",item)
                    return item;
                }

                if(rel && rel.id && rel.id===data){
                    return rel;
                }

                return  {
                    data: {
                        id: data
                    }
                };
            }

            // update relationships
            Object.getOwnPropertyNames(_item.relationships).forEach(function (relName) {
                if (!updateData.hasOwnProperty(relName)) {
                    return;
                }
                if(updateData[relName]===null) {
                    _item.relationships[relName] = null;
                    return;
                }
                this.relationships[relName] = updateRelation(this.relationships[relName],updateData[relName]);
                delete updateData[relName];
            }, _item);



            // check attributes
            Object.getOwnPropertyNames(updateData).forEach(function (attrName) {
                if( updateData[attrName] && typeof updateData[attrName]==="object") {
                    if(!this.strict && typeof this.relationships[attrName] === "undefined" ) {
                        // console.log("Add extra relation");
                        this.relationships[attrName] = updateRelation(this.relationships[attrName],updateData[attrName]);
                    }
                    return;
                }

                if(!this.shadow.attributes.hasOwnProperty(attrName) ) {
                    if(!this.strict) {
                        // console.log("Attr '"+attrName+"' not existing and strict mode off => add attr to update");
                        this.attributes[attrName] = updateData[attrName];
                    }
                    return;
                }

                // update only if different from prev value
                if(updateData[attrName]!==this.shadow.attributes[attrName]) {
                    // console.log("Attr '"+attrName+"'  update value '"+updateData[attrName]+"' differs in value than current value '"+this.attributes[attrName]+"' => add to update");
                    this.attributes[attrName] = updateData[attrName];
                }

            }, _item);

            // console.log("item",updateData,Object.assign({},_item))


            if(updateOptions.sync) {
                return perform_update(updateOptions);
            }

            return new Promise(function (resolve) {
                _item.syncOp = perform_update;
                _item.views.forEach(function (view){
                    if(updateOptions.rerender) {
                        view.render();
                    }
                });
                resolve();
            });
        };

        _item.remove = function() {
            return new Promise(function (resolve, reject) {
                let ps = [];
                for(let i=_item.views.length-1 ; i>=0 ; i--) {
                    ps.push(_item.views[i].remove());
                }


                let collection = _item.collection;
                if(collection) {
                    ps.push(collection.removeItem(_item));
                }
                Promise.all(ps)
                    .then(()=>{
                        if(callbacks["remove"])
                            callbacks["remove"].forEach((cb)=>new Promise(()=>cb(_item)));
                        if(collection)
                            collection.onupdate();
                    })
                    .finally(()=>resolve());
                // Promise.all(ps).then((data)=>resolve(data)).catch((err)=>reject(err));
            });
        };

        /**
         * if there is a pending sync operation and that operation is not the same as the current operation, throw an error
         * @param syncOp Function - sync function to be validated
         */
        function check_pending_sync(syncOp) {
            if(!_item.syncOp || _item.syncOp===syncOp)
                return;
            throw {
                message: "Unsynced changes. Sync first before allowed to make other changes",
                syncOp: _item.syncOp,
                checkOp: syncOp
            };
        }
        /**
         * delete item
         */
        _item.delete = function (ops) {
            let deleteOps = {
                sync: true,
            };

            if(ops && ops.constructor===Object) {
                Object.assign(deleteOps,ops);
            }

            function deleteOp() {
                return new Promise((resolve,reject) => {
                    // set deleteUrl
                    _item.deleteUrl = _item.deleteUrl  ? _item.deleteUrl : _item.url + "/" + _item.id;

                    function onDeleteFail(resp) {
                        if(apiatorDebug) console.log("failed delete",resp);
                        reject(resp);
                    }

                    // remove from storage
                    storage.delete(_item,_item.deleteUrl,{})
                        .then(
                            function () {
                                _item.remove().then(()=>resolve());
                            }
                        )
                        .catch(reject);
                });
            }

            if(deleteOps.sync) {
                return deleteOp();
            }

            return new Promise(function (resolve) {
                _item.syncOp = deleteOp;
                _item.remove().then(()=>resolve());
            });

        };

        _item.getUtilities = function () {
            return utilities;
        };

        /**
         * render Item
         * @param collectionView
         */
        _item.render = function (collectionView,addontop=false) {
            if(apiatorDebug) console.log("Render from item",_item.render.caller,_item);
            _item.views.forEach(function (view) {
                if(typeof collectionView==="undefined") {
                    if(apiatorDebug) console.log("collectionView is undefined so render view");
                    view.render();
                    return;
                }
                if(view.container === collectionView) {
                    if(apiatorDebug) console.log("collectionView matches view container so render view");
                    view.render(false,addontop);
                }
            });
        };

        return _item;
    }


    /**
     * Functions to perform usefull stuff
     * @type {{fillForm: fillForm, captureFormSubmit: captureFormSubmit}}
     */
    let utilities = {
        // fill form fields with data from instance
        fillForm: function(form,instance) {
            form = $(form)[0];
            if($(form).prop("tagName")!=="FORM"	)
                return null;

            if(!instance || !instance.hasOwnProperty("attributes"))
                return null;

            let attributes = {};

            form = $(form)[0];

            Object.getOwnPropertyNames(instance.attributes).forEach(function (attrName) {
                if(!form.elements.hasOwnProperty(attrName))
                    return;
                let val = instance.attributes[attrName];
                let inp = $(form.elements[attrName]);
                if(instance.attributes[attrName] && typeof instance.attributes[attrName]==="object" && instance.attributes[attrName].hasOwnProperty("id"))
                    val = instance.attributes[attrName].id;
                if(inp.attr('type')==='date') {
                    val = val ? val.substr(0, 10) : val;
                }
                inp.val(val);


            });

            if(!instance.relationships )
                return ;

            Object.getOwnPropertyNames(instance.relationships).forEach(function (relName) {
                if(!form.elements.hasOwnProperty(relName))
                    return;

                if(!instance.relationships[relName])
                    return $(form.elements[relName]).val(null);
                let rel = instance.relationships[relName];
                let formEl = form.elements[relName];
                let $formEl = $(formEl);

                if(rel.constructor===Array) {

                    let vals = [];
                    rel.forEach(function (relItem) {
                        vals.push(relItem.id);
                    });
                    $formEl.val(vals);
                }
                else {
                    if(apiatorDebug) console.log("set ",relName,rel);
                    if(formEl.tagName==="SELECT") {
                        let lbl = $formEl.data("label");
                        let lblVal = rel.hasOwnProperty(attributes) && rel.attributes[lbl] ? rel.attributes[lbl] : rel.id;

                        $("<option>")
                            .val(rel.id)
                            .text(lblVal)
                            .appendTo($formEl);
                    }
                    $formEl.val(rel.id);
                }

            });
        },



        // capture form submit event and redirect it to callback
        captureFormSubmit: function(form,cb) {
            if($(form).prop("tagName")!=="FORM" || typeof cb!=="function")
                return;

            // setup submit processing
            $(form).off("submit").on("submit",function(event) {
                // console.log("form submit triggered",event);
                event.preventDefault();
                let frm = $(form)[0];
                cb(utilities.fetchFormData(frm),event);
            });

            return $(form);
        },

        fetchFormData: function (frm) {
            let formElements = {};
            Object.getOwnPropertyNames( frm.elements).forEach(function (item) {
                let $item = $(frm.elements[item]);
                if(!$item.attr("name") || $item.attr("name")==="")
                    return;
                if($item.attr("type")==="checkbox" &&  !$item[0].checked) {
                    return;
                }
                let name = $item.attr("name");
                let tmp;
                if(tmp = /(\w+)\[\]/.exec(name)) {
                    if(!formElements[tmp[1]])
                        formElements[tmp[1]] = []
                    else
                        formElements[tmp[1]].push($item.val());
                }
                formElements[name] = $item.val();
            });
            return formElements;
        },

        /**
         *
         * @param form HTML Form element
         */
        extractFormData: function (form) {
            form = $(form)[0];
            let formElements = {};
            Object.getOwnPropertyNames( form.elements).forEach(function (item) {
                let $item = $(form.elements[item]);
                if(!$item.attr("name") || $item.attr("name")==="")
                    return;
                if($item.attr("type")==="checkbox" &&  !$item[0].checked) {
                    return;
                }
                formElements[$item.attr("name")] = $item.val();
            });
            return formElements;
        }
    };


    /**
     *
     * @param params
     * @returns {{template: null, container: null, item: null, el: null}}
     */
    function ItemView(params)
    {
        // params is actually an existing ItemView
        if(params.isView) {
            return params;
        }

        // params is actually a jquery object or an html node
        if(params.length || params.nodeName) {
            if(apiatorDebug) console.log("params is actually a jquery object or an html node",params);
            let $el = $(params);
            if($el.data("view")) {
                return $el.data("view");
            }

            let tmp = $("<div>").append($el.clone(true));
            let html = tmp.html()
                .replace(/&lt;%/gi, '<%')
                .replace(/&lt;/gi, '<')
                .replace(/%&gt;/gi, "%>")
                .replace(/&gt;/gi, '>')
                .replace(/&amp;/gi, "&");

            params = {
                template: template(html),
                el: $el
            };
            if($el.attr("id")) {
                params.id = $el.attr("id");
            }
            tmp.remove();
        }

        let _itemview = {
            type: "ItemView",
            dataBindings: null,
            template: null,
            container: null,
            collectionView: null,
            item: null,
            el: null,
            id: uid(),
            isView: true
        };

        try {
            params = parseOptions(params);
        }
        catch (e) {
            throw ["Error on ItemView",_itemview,e];
        }

        Object.assign(_itemview,params);


        if(_itemview.el !== null) {
            _itemview.dataBindings = getBoundObjects(_itemview.el);
        }

        let a = {}

        let tmp = {};
        Object.assign(tmp,_itemview);

        // todo: remove this check in future release
        // if (!_itemview.template) {
        // 	throw "Invalid ItemView template";
        // }

        function createElementFromTemplate() {
            if(_itemview.template==null) {
                dbg('Warning: no template defined. Nothing to render');
                return null;
            }
            let el;
            try {
                let html = _itemview.template(_itemview.item);
                // console.log(html);
                el = $(html)
                    .attr("data-type", "item")
                    .attr("id", _itemview.id)
                    .data("view", _itemview)
                    .data("instance", _itemview.item);
            }
            catch (e) {
                console.log("Error create view from template",e)
                el = $("<div>Could not render view: <strong>"+e.toString()+"</strong></div>")
            }

            _itemview.dataBindings = _itemview.dataBindings ? _itemview.dataBindings : _itemview.item.collection.view.dataBindings;

            for(let key in _itemview.dataBindings) {
                el.data(key,_itemview.dataBindings[key]);
                el.find("*").data(key,_itemview.dataBindings[key]);
            }

            el.find("*").data("instance",_itemview.item);
            return el;
        }

        _itemview.unbind = function() {
            this.item.unbindView(this);
        };

        /**
         *
         */
        function interpolateInstance(_itemview) {
            if(apiatorDebug) console.log("try to interpolateInstance",_itemview.el,_itemview.item.attributes);
            let includes = _itemview.el.find("[is=apiator]");
            if(!includes.length) {
                if(apiatorDebug) console.log("nothing to interpolate");
                return;
            }
            if(apiatorDebug) console.log("do interpolation",_itemview,includes);

            includes.each(function () {
                let $el = $(this);
                $el.removeAttr("is").removeData("instance").data("parentview",_itemview);
                if(apiatorDebug) console.log("Include to interpolate",$el);

                let options = {returninstance:true};
                let url = $el.data("url");
                let dtBind = $el.data("bind");

                if(dtBind) {
                    options.dontload = true;
                    let data = _itemview.item;

                    if(apiatorDebug) console.log("databind present",_itemview,data);

                    let segments = dtBind.split(".");

                    for(let i = 0;i<segments.length;i++) {
                        if(typeof data[segments[i]]==="undefined") {
                            throw "data bind path '"+dtBind+"' does not resolve to a valid member inside the instance tree";
                        }
                        data = data[segments[i]];
                    }
                    if(!data) {
                        return;
                    }
                    if(apiatorDebug) console.log("data.constructor",data,data.constructor);
                    options.resourcetype = (data.hasOwnProperty("length"))? "collection" :"item";

                    if(apiatorDebug) console.log("Apiate on ",options,$el,data);
                    let el = $el.apiator(options)
                        .loadFromData(data).render();

                    if(url!==undefined) {
                        el.setUrl(url)
                    }

                    if(segments[0] ==="relationships") {
                        _itemview.item.relationships[segments[1]] = el;
                    }

                    if(apiatorDebug) console.log("Element rendered",el,$el);
                    return;
                }
                //
                // if(url) {
                // 	$el.apiator(options)
                // 		.loadFromData(data)
                // 		.render();
                // }


            });
        }

        let callbacks = {};
        _itemview.on = function(event,cb) {
            if(!callbacks[event]) {
                callbacks[event] = [];
            }
            callbacks[event].push(cb);
            return _itemview;
        };

        function afterrender(view) {
            if(!callbacks.afterrender) {
                return
            }

            callbacks.afterrender.forEach((cb)=>cb(view))
        }

        /**
         *
         * @param doNotAttachToContainer should be true when the element should not be rendered into the DOM
         * @returns {null|jQuery}
         */
        _itemview.render = function (doNotAttachToContainer=false,addontop=false) {

            // console.log("Render view",_itemview.render.caller,_itemview);

            // render element
            let renderedEl = createElementFromTemplate();
            if(!renderedEl) {
                return null;
            }

            if(doNotAttachToContainer) {
                if(apiatorDebug) console.log("doNotAttachToContainer",_itemview);
                _itemview.el = renderedEl;
                interpolateInstance(_itemview);
                return _itemview.el;
            }

            // replace already rendered element
            // if(_itemview.el && _itemview.el.parents("body").length) {
            if(_itemview.el) {
                // console.log("replace already rendered element",renderedEl,_itemview.el);
                let oldEl = _itemview.el;
                _itemview.el = renderedEl.insertBefore(oldEl[0]);

                oldEl.remove();
                interpolateInstance(_itemview);
                afterrender(_itemview.el)
                return _itemview;
            }

            _itemview.el = renderedEl;
            afterrender(_itemview.el);

            if(!_itemview.container) {
                return _itemview;
            }
            //
            // addontop = typeof addontop!=="undefined" ? addontop :
            //     (_itemview.item.collection ? _itemview.item.collection.addontop : false );

            // if(addontop) {
            //     let children = _itemview.container.el.children();
            //     if(children.length) {
            //         if(apiatorDebug) console.log("Append item on top of ",children[0]);
            //         _itemview.el.insertBefore(children[0]);
            //     }
            // }
            // else {

            _itemview.el.appendTo(_itemview.container.el);
            // }

            interpolateInstance(_itemview);
            // _itemview.container.el.append(_itemview.el);


            return _itemview;

            //
            //
            // renderedEl.insertBefore(_itemview.el[0]);
            //
            // this.el.remove();
            // this.el = renderedEl;
            //
            //
            // return this.el;
        };

        _itemview.renderEmpty = function(returnView) {
            if(_itemview.item.emptyview && this.el) {
                this.el.replaceWith(_itemview.item.emptyview.clone(true).css("display","block"));
            }
        };

        _itemview.remove = function (idx) {
            return new Promise(function (resolve) {
                if(_itemview.item.collection && _itemview.item.collection.onafterrender){
                    // console.trace("onafterrender")
                    _itemview.item.collection.onafterrender(_itemview.item.collection);
                }
                _itemview.el.fadeOut({
                    complete: ()=>{
                        _itemview.el.remove();
                        resolve();
                    }
                });
            })


        };
        return _itemview;
    }


    /**
     * URL object factory method
     * @param url
     * @returns {{path: string, protocol: string, fragment: string, fqdn: string, port: string, toString: (function(): string), parameters: string}|null}
     * @constructor
     */
    function OldURL(url)
    {


        if(!url)
            return null;

        if(typeof url==="object" && url.hasOwnProperty("protocol") )
            return url;

        if(url.constructor!==String) {
            console.log("URL is not a string",url)
            throw "URL is not a string: " + url.toString();
        }

        let regExp = /^((?:([a-z]+):)([\/]{2,3})([\w\.\-\_]+)(?::(\d+))?)?(?:(\/?[^?#]*))?(?:\?([^#]*))?(?:#(.*))?$/i;
        let parts = regExp.exec(url);

        let urlObj = {
            protocol: null,
            fqdn: null,
            port: null,
            path: null,
            parameters: null,
            fragment: null,
            toString: function () {
                // return url;
                let str = "";
                if(this.protocol && this.fqdn) {
                    str += this.protocol+"://"+this.fqdn;
                    if(this.port) {
                        str += ":"+this.port;
                    }
                }

                if(this.path) {
                    str += this.path;
                }
                if(this.parameters) {
                    str += "?" + this.parameters.toString();
                }
                if(this.fragment) {
                    str += "#" + this.fragment;
                }
                return str;
            }
        };

        if(typeof parts[2]!=="undefined") {
            urlObj.protocol = parts[2];
        }
        if(typeof parts[4]!=="undefined") {
            urlObj.fqdn = parts[4];
        }
        if(typeof parts[5]!=="undefined") {
            urlObj.port = parts[5];
        }
        if(typeof parts[6]!=="undefined") {
            urlObj.path = parts[6];
        }
        if(typeof parts[7]!=="undefined") {
            urlObj.parameters = parts[7];
        }
        if(typeof parts[8]!=="undefined") {
            urlObj.fragment = parts[8];
        }



        // if(urlObj.)

        if(urlObj.parameters) {
            let tmp = urlObj.parameters.split("&");
            urlObj.parameters = {};
            tmp.forEach(function (item) {
                if(!item || item==="")
                    return;
                let eqPos = item.indexOf("=");
                if(eqPos===-1)
                    urlObj.parameters[item] = "";
                urlObj.parameters[item.substr(0,eqPos)] = item.substr(eqPos+1);
            });

        }
        else {
            urlObj.parameters = {};
        }

        urlObj.parameters.toString = function () {
            let paras = [];
            for(let para in this) {
                if(this.hasOwnProperty(para) && para!=="toString")
                    paras.push(para+"="+this[para]);
            }
            return paras.join("&");
        };


        return urlObj;
    }

    function URL(url) {
        if(!url)
            return null;

        if(typeof url==="object" && url.hasOwnProperty("protocol") )
            return url;

        if(url.constructor!==String) {
            console.log("URL is not a string",url)
            throw "URL is not a string: " + url.toString();
        }

        let regExp = /^((?:([a-z]+):)([\/]{2,3})([\w\.\-\_]+)(?::(\d+))?)?(?:(\/?[^?#]*))?(?:\?([^#]*))?(?:#(.*))?$/i;
        let parts = regExp.exec(url);

        let urlObj = {
            protocol: null,
            fqdn: null,
            port: null,
            path: null,
            parameters: null,
            fragment: null,
            toString: function () {
                // return url;
                let str = "";
                if(this.protocol && this.fqdn) {
                    str += this.protocol+"://"+this.fqdn;
                    if(this.port) {
                        str += ":" + this.port;
                    }
                }

                if(this.path) {
                    str += this.path;
                }
                if(this.parameters) {
                    str += "?" + this.parameters.toString();
                }
                if(this.fragment) {
                    str += "#" + this.fragment;
                }
                return str;
            }
        };

        if(typeof parts[2]!=="undefined") {
            urlObj.protocol = parts[2];
        }
        if(typeof parts[4]!=="undefined") {
            urlObj.fqdn = parts[4];
        }
        if(typeof parts[5]!=="undefined") {
            urlObj.port = parts[5];
        }
        if(typeof parts[6]!=="undefined") {
            urlObj.path = parts[6];
        }
        if(typeof parts[7]!=="undefined") {
            urlObj.parameters = parts[7];
        }
        if(typeof parts[8]!=="undefined") {
            urlObj.fragment = parts[8];
        }



        // if(urlObj.)

        if(urlObj.parameters) {
            let tmp = urlObj.parameters.split("&");
            urlObj.parameters = {};
            tmp.forEach(function (item) {
                if(!item || item==="")
                    return;
                let eqPos = item.indexOf("=");
                if(eqPos===-1)
                    urlObj.parameters[item] = "";
                urlObj.parameters[item.substr(0,eqPos)] = item.substr(eqPos+1);
            });

        }
        else {
            urlObj.parameters = {};
        }

        urlObj.parameters.toString = function () {
            let paras = [];
            for(let para in this) {
                if(this.hasOwnProperty(para) && para!=="toString")
                    paras.push(para+"="+this[para]);
            }
            return paras.join("&");
        };


        return urlObj;
    }


    function parse_data_for_insert_or_update(itemData)
    {

        if(itemData===null) {
            return null;
        }

        if(typeof itemData !== "object") {
            throw "Invalid item data: "+itemData;
        }

        if(itemData.constructor===Array || (itemData.hasOwnProperty("items") && itemData.hasOwnProperty("length"))) {
            let resource = [];
            itemData.forEach(function (item) {
                resource.push(parse_data_for_insert_or_update(item));
            });
            return resource;
        }
        console.log(itemData);

        if(itemData.constructor!==Object) {
            throw "Invalid case";
        }

        let resource = {};


        // if(!itemData.hasOwnProperty("type") && !itemData.hasOwnProperty("attributes") ) {
        if(!itemData.hasOwnProperty("attributes") ) {
            let tmp = {attributes:{}};
            if(itemData.hasOwnProperty("type")) {
                tmp.type = itemData.type;
            }
            Object.assign(tmp.attributes, itemData);
            itemData = tmp;
        }
        // else if(itemData.hasOwnProperty("type")) {
        // 	resource.type = itemData.type;
        // }

        Object.getOwnPropertyNames(itemData.attributes).forEach(function (attr) {
            if(itemData.attributes[attr] && typeof itemData.attributes[attr]==="object") {
                if(!resource.relationships) {
                    resource.relationships = {}
                }
                resource.relationships[attr] = {
                    data: parse_data_for_insert_or_update(itemData.attributes[attr])
                };
                return;
            }
            if(!resource.attributes) {
                resource.attributes = {}
            }
            resource.attributes[attr] = itemData.attributes[attr];
        });

        return resource;
    }

    /**
     *
     * @param opts
     * @returns {{template: null, view: null, total: null, offset: number, navtype: string, pageSize: number, paging: null, url: null}}
     */
    function Collection(opts)
    {

        let allowedOptions = ["url","deleteUrl","insertUrl","updateUrl","paging"
            ,"view","offset","pageSize","template","type","emptyview","filter","pagesize",
            "resourcetype","dataBindings","addontop","template"];

        let iterator = -1;
        let _collection = {
            url: null,
            deleteUrl: null,
            insertUrl: null,
            updateUrl: null,
            paging:null,
            view: null,
            offset: 0,
            total: null,
            pageSize: 100,
            template: null,
            navtype: "page",
            type: null,
            emptyview: null,
            length: 0,
            items: []
        };

        const callbacks = {};
        _collection.on = function(eventName,cb) {
            if(typeof callbacks[eventName]==="undefined") {
                callbacks[eventName] = [];
            }
            callbacks[eventName].push(cb);
            return _collection;
        };

        _collection.showlisteners = function() {
            console.log(callbacks);
        };
        _collection.each = function(func) {
            for(let i=0;i<_collection.length;i++) {
                func(_collection[i]);
            }
        };
        _collection.next = function() {
            iterator++;
            if(iterator+1>_collection.length) {
                iterator = -1;
                return false;
            }
            return  _collection[iterator];
        };
        _collection.prev = function() {
            iterator--;
            if(iterator-1<0) {
                iterator = -1;
                return false;
            }
            return  _collection[iterator];
        };
        _collection.rewind = function() {
            iterator = -1;
        };
        _collection.key = function() {
            return iterator;
        };


        _collection.removeItem = function(item) {
            for(var i=0;i<_collection.items.length;i++) {
                if(_collection.items[i].id===item.id) {
                    _collection.items.splice(i,1);
                    for(var j=i;j<_collection.length-1;j++) {
                        _collection[j] =_collection[j+1];
                    }
                    delete _collection[j];
                    _collection.length--;
                    break;
                }
            }
        };


        _collection.setPageSize = function(val) {
            if(/^\d+$/.test(val)) {
                _collection.pageSize = val;
                return true;
            }

            return false;
        };

        _collection.empty = function() {

            return _collection.clear();
        };

        _collection.setOffset = function(val) {
            if(/^\d+$/.test(val)) {
                _collection.offset = val;
                return true;
            }
            return false;

        };

        /**
         * bulk update
         * @param data
         */
        _collection.update = function(data) {
            throw "Not implemented... yet";
        };

        _collection.setUrl = function(url) {
            
            if(!url) {
                return ;
            }
            
            
            if(url.constructor===String || url.hasOwnProperty("fqdn")) {
                this.url = URL(url);
                this.setPageSize(this.url.parameters["page["+_collection.type+"][limit]"]);
                this.setOffset(this.url.parameters["page["+_collection.type+"][offset]"]);

                this.updateUrl = Object.assign({},this.url);
                this.deleteUrl = Object.assign({},this.url);
                this.insertUrl = Object.assign({},this.url);
            }

            if(url.hasOwnProperty("url")) {
                this.url = URL(url.url);
                this.setOffset(this.url.parameters["page["+_collection.type+"][offset]"]);
                this.setPageSize(this.url.parameters["page["+_collection.type+"][limit]"]);
            }
            if(url.hasOwnProperty("updateUrl"))
                this.updateUrl = URL(url.updateUrl);
            if(url.hasOwnProperty("deleteUrl"))
                this.deleteUrl = URL(url.deleteUrl);
            if(url.hasOwnProperty("insertUrl"))
                this.insertUrl = URL(url.insertUrl);

            
            this.type = this.url.path.split("/").pop().split("?")[0].split("#")[0];
            return this;
        };

        try {
            opts = parseOptions(opts);
        }
        catch (e) {
            throw ["Error on Collection init",e];
        }

        if(opts.ajaxOpts) {
            _collection.ajaxOpts = opts.ajaxOpts;
        }



        let options = {};
        console.log(opts,Object.getOwnPropertyNames(opts));
        
        Object.getOwnPropertyNames(opts).forEach(function(key){
            if(allowedOptions.indexOf(key)!==-1)    
                options[key] = opts[key];
        })


        //console.log(options,opts,Object.keys(options),Object.keys(opts));
        
        Object.assign(_collection,options);
        //Object.assign(_collection,opts);

        
        _collection.setUrl(_collection.url);
        // _collection.url = URL(_collection.url);
        if(_collection.deleteUrl) {
            _collection.setUrl({deleteUrl:_collection.deleteUrl});
        }
        if(_collection.updateUrl) {
            _collection.setUrl({updateUrl:_collection.updateUrl});
        }
        if(_collection.insertUrl) {
            _collection.setUrl({insertUrl:_collection.insertUrl});
        }

        if(_collection.view) {
            _collection.view.collection = _collection;
        }

        // if(_collection.url && _collection.url.parameters) {
        // 	_collection.setOffset(_collection.url.parameters["page["+_collection.type+"][offset]"]);
        // 	_collection.setPageSize(_collection.url.parameters["page["+_collection.type+"][limit]"]);
        // }

        if(_collection.total) {
            _collection.total = _collection.total * 1;
        }

        if(["page","scroll"].indexOf(_collection.navtype)===-1)
            throw "Invalid navigations type. Should be page or scroll";

        let storage = opts.hasOwnProperty("storage") ? opts.storage : (
            opts.hasOwnProperty("ajaxOpts") ? Storage(opts.ajaxOpts) : Storage()
        );
        /**
         *
         * @param data
         * @returns {{template: null, insertUrl: null, offset: number, pageSize: number, paging: null, type: null, url: null, view: null, total: null, navtype: string, updateUrl: null, deleteUrl: null, emptyview: null}|{relationships: null, view: null, attributes: null, id: null, collection: null, type: null, url: null}}
         */
        _collection.receiveRemoteData = function (data) {
            if(apiatorDebug) console.log("Remote data received",data);

            data = parse(data);

            if(data == null)
                return;

            // received data is a collection
            if(data.constructor===Array) {
                if(apiatorDebug) console.log("Append multiple items to collection");
                if(_collection.items.length===0) {
                    _collection.view.reset(true);
                }
                data.forEach(function (item) {
                    appendItemToCollection(_collection,_collection.loadItem(item,true));
                });

                // this.trigger("load",{data: data});
                return _collection.render();
            }

            // received data is an item => add it
            if(data.constructor===Object) {
                if(_collection.items.length===0) {
                    _collection.view.reset(true);
                }
                if(apiatorDebug) console.log("Append single item to collection");
                // this.trigger("load",{data: data});
                // return  appendItemToCollection(_collection,_collection.loadItem(data),true);
                let newItem = _collection.loadItem(data);

                newItem.render(_collection.view,_collection.addontop);
                if(_collection.onafterrender){
                    // console.trace("onafterrender")
                    _collection.onafterrender(_collection);
                }
                return newItem;
            }




        };

        function appendItemToCollection(collection,item,render) {
            if(render) {
                _collection.render();
            }
            return item;
        }

        /**
         *
         * @param data
         */
        _collection.loadFromData = function (data) {
            if(apiatorDebug) console.log("collection load from data",data);

            if( data===null || typeof data!=="object" || data.constructor!==Array ) {
                if(apiatorDebug) console.log("cannot load ",data, " into collection ",_collection);
                return this;
            }

            if(_collection.navtype==="page")
                _collection.items = [];

            data.forEach(function (item) {
                _collection.loadItem(item);
            });

            if(_collection.view) {
                _collection.view.render();
            }
            else {
                console.log("collection does not have a view ",_collection);
            }
            if(callbacks.load) callbacks.load.forEach((cb)=>new Promise(()=>cb(_collection)));
            return _collection;
        };

        _collection.clear = function() {
            _collection.items = [];
            _collection.render();
            return _collection;
        };


        /**
         *
         * @returns {{template: null, insertUrl: null, offset: number, pageSize: number, paging: null, type: null, url: null, view: null, total: null, navtype: string, updateUrl: null, deleteUrl: null, items: [], emptyview: null}}
         */
        _collection.render = function() {
            // console.log("Render collection",_collection,_collection.onafterrender,typeof _collection.onafterrender==="function");
            if(_collection.view) {
                _collection.view.render();
            }
            // console.log("afterrender",callbacks,_collection);

            if(callbacks.afterrender) {
                callbacks.afterrender.forEach((cb)=>typeof cb==="function" && cb(_collection));
            }
            if(_collection.onafterrender && typeof _collection.onafterrender==="function") {
                _collection.onafterrender(_collection);
            }
            return _collection;

        };

        /**
         *
         * @returns {Promise<unknown>}
         */
        _collection.loadFromRemote = function() {
            return _collection.load_from_data_source();
        };
        _collection.reload = _collection.loadFromRemote;
        _collection.refresh = _collection.loadFromRemote;


        /**
         * sync with datasource
         * @returns {Promise<unknown>}
         */
        _collection.load_from_data_source = function () {
            let loader = overlay.clone().insertBefore(_collection.view.el)
                .width($(_collection.view.el).width())
                .height($(_collection.view.el).height());
            if(_collection.onbeforeload && typeof _collection.onbeforeload==="function") {
                console.log("Exec onbeforeload")
                _collection.onbeforeload(_collection);
            }

            return  new Promise(function (resolve,reject) {
                if(!_collection.url) {
                    throw("No valid URL provided");
                }

                if(typeof _collection.offset!== "undefined" && _collection.offset!==null) {
                    _collection.url.parameters["page["+_collection.type+"][offset]"] = _collection.offset;
                }

                if(typeof _collection.pageSize!== "undefined" && _collection.pageSize!==null) {
                    _collection.url.parameters["page["+_collection.type+"][limit]"] = _collection.pageSize;
                }

                storage.read(_collection,_collection.url,{})
                    .then(function(res)
                    {
                        _collection.clear();
                        _collection.receiveRemoteData(res.data);
                        if(callbacks["load"]) callbacks["load"].forEach((cb)=>new Promise(()=>cb(_collection)));
                        loader.remove();
                        resolve(_collection);
                    })
                    .catch(function(jqXHR, textStatus, errorThrown)
                    {
                        _collection.fail(jqXHR, textStatus, errorThrown);
                        reject(jqXHR);
                    });
            });

        };

        /**
         * @todo clarifiy thats this function used for
         * @param xhr
         * @param txt
         * @param err
         */
        _collection.fail = function (xhr, txt, err) {
            if(apiatorDebug) console.log("Fail to load collection",xhr, txt, err,_collection);
        };





        /**
         *
         * @param itemData
         * @returns {{data: null}}
         */

        /**
         *
         * @param itemData
         */
        _collection.createItem = function(itemData) {
            return _collection.append(itemData);
        };

        _collection.newItem = function(itemData) {
            return _collection.append(itemData);
        };


        _collection.onupdate = function() {
            console.log("onupdate");
            if(!callbacks.update)
                return;
            callbacks.update.forEach((cb)=>cb(_collection));
        };



        _collection.append = function(itemData) {
            let jsonApiDoc = {data: parse_data_for_insert_or_update(itemData)};
            if(_collection.type) {
                jsonApiDoc.type = _collection.type;
            }

            return new Promise(function (resolve,reject) {
                if(!_collection.insertUrl) {
                    _collection.insertUrl = _collection.url;
                }

                storage
                    .create(_collection,_collection.insertUrl,{contentType:"application/vnd.api+json"},JSON.stringify(jsonApiDoc))
                    .then(function (resp) {
                        let data = resp.data;
                        let newItem = _collection.receiveRemoteData(data);
                        resolve(newItem);
                        _collection.onupdate();
                    })
                    .catch(function (resp) {
                        if(apiatorDebug) console.log("fail to receive data",resp);
                        reject(resp);
                    });
            });
        };

        /**
         *
         * @param itemData
         * @param render
         * @returns {_item|*|{template: null, insertUrl: null, offset: number, length: number, pageSize: number, paging: null, type: null, url: null, view: null, total: null, navtype: string, updateUrl: null, deleteUrl: null, items: [], emptyview: null}|void}
         */
        _collection.loadItem = function (itemData) {
            if(!itemData)
                return null;
            // throw new Error("asda");

            let opts = {
                type: _collection.type,
                collection: _collection
            };

            if(itemData.id && _collection.url) {
                opts.url = Object.assign({},_collection.url);
                opts.url.path += "/" + itemData.id;

                opts.updateUrl = _collection.updateUrl ? Object.assign({},_collection.updateUrl) :  Object.assign({},_collection.url);
                opts.updateUrl.path += "/" + itemData.id;

                opts.deleteUrl = _collection.deleteUrl ? Object.assign({},_collection.deleteUrl) :  Object.assign({},_collection.url);
                opts.deleteUrl.path += "/" + itemData.id;
            }


            let newItem = Item(opts)
                .bindView(ItemView({
                    template: _collection.template,
                    container: _collection.view
                }))
                .loadFromData(itemData);

            if(_collection.addontop) {
                console.log("Add on top");
                _collection.items.unshift(newItem);
                for(let i=_collection.length;i>0;i--) {
                    _collection[i]=_collection[i-1];
                }
                _collection[0] = newItem;
            }
            else {
                _collection.items.push(newItem);
                _collection[_collection.length] = newItem;
                _collection.length++;
            }

            return newItem;
        };


        /**
         *
         * @param data
         */
        function parse(data) {
            flattenDoc(data);
            let doc = buildDb(data);

            if(apiatorDebug) console.log("parse data",data);


            if (!data.hasOwnProperty("data"))
                return data;


            if (data.hasOwnProperty("meta")) {
                if (data.meta.hasOwnProperty("totalRecords"))
                    _collection.total = data.meta.totalRecords*1;
                if (data.meta.hasOwnProperty("offset"))
                    _collection.offset = data.meta.offset;

            }
            return data.data;
        }

        _collection.getUtilities = function () {
            return utilities;
        };
        if(typeof opts.listeners==="object"){
            for(let event in _collection.listeners){
                _collection.on(event,_collection.listeners[event]);
            }
        }

        return _collection;
    }


    /**
     *
     * @param options
     * @returns {{container: null, el: null, collection: null, itemsContainer: null}}
     */
    function CollectionView(options)
    {
        let _collectionView = {
            el: null,
            type: "CollectionView",
            container: null,
            collection: null,
            itemsContainer: null,
            allowempty: true
        };



        try {
            Object.assign(_collectionView,parseOptions(options));
        }
        catch (e) {
            throw ["Error on CollectionView init",e];
        }


        _collectionView.dataBindings = getBoundObjects(_collectionView.el);

        /**
         *
         * @returns {{container: null, el: null, collection: null, allowempty: boolean, itemsContainer: null}}
         */
        _collectionView.reset = function (force) {
            if(this.allowempty || force) {
                _collectionView.el.empty();
            }
            return _collectionView;
        };

        /**
         *
         * @returns {_collectionView}
         */
        _collectionView.render = function () {
            if(apiatorDebug) console.log("Render _collectionView",_collectionView.render.caller, _collectionView.collection,);

            if(_collectionView.collection.navtype==="page") {
                _collectionView.reset();
            }

            if(_collectionView.collection.items.length===0) {
                _collectionView.renderEmpty();
            }

            _collectionView.collection.items.forEach(function (item) {
                item.render(_collectionView);
                // item.views.forEach(function (view) {
                // 	view.render(true);
                // 	if(view.container===this) {
                // 		this.append(view.render(true));
                // 	}
                // },this);

            },_collectionView);


            if (_collectionView.collection.paging && typeof _collectionView.collection.paging==="object") {
                _collectionView.collection.paging.render();
            }

            return _collectionView;
        };

        _collectionView.renderEmpty = function() {
            if(!this.collection.emptyview)
                return this;
            this.reset().el.append(this.collection.emptyview);
        };


        /**
         *
         * @param itemView
         * @param addOnTop
         * @returns {*|ActiveX.IXMLDOMNode}
         */
        // _collectionView.append = function(itemView,addOnTop) {
        // 	if(apiatorDebug) console.log("Append item to collectionView",_collectionView,itemView);
        //
        // 	if(addOnTop) {
        // 		let children = _collectionView.el.children();
        // 		if(children.length) {
        // 			if(apiatorDebug) console.log("Append item on top of ",children[0]);
        // 			return  itemView.el.insertBefore(children[0]);
        // 		}
        // 	}
        // 	return itemView.el.appendTo(_collectionView.el);
        // };

        return _collectionView.reset();

    }





    function getBoundObjects(el) {
        let db = {};
        if($(el).length===0) {
            return db;
        }

        let boundData = $(el).data();
        for (let key in boundData) {
            if (typeof boundData[key]==="object" && key!=="instance") {
                db[key] = boundData[key];
            }
        }
        return db;
    }

    function sortNow ($lnk,setDir) {
        console.log($lnk);
        let fld = $lnk.data("sortfld");
        let oldDir = $lnk.data("sortdir");
        let $sortUp = $lnk.find(".sort-up");
        let $sortDown = $lnk.find(".sort-down");
        let $sortDefault = $lnk.find(".sort-default");
        let dir;
        let doNotLoad = false;
        switch(oldDir) {
            case "up":
                dir = "down";
                break;
            case "down":
                dir = null;
                break;
            default:
                dir = "up";
                break;
        }

        if(typeof setDir!=="undefined" && ["up","down",null].indexOf(setDir)!==-1) {
            dir = setDir;
            doNotLoad = true;
        }

        let inst = $lnk.data("instance");
        let sort = inst.url.parameters.hasOwnProperty("sort")?inst.url.parameters.sort:"";
        let sortArr = [];
        sort.split(",").forEach(function(item){
            let res = /^(-*)([a-z0-9\-\_]+)$/.exec(item.trim());
            if(!res)
                return;
            if(res[2]==fld)
                return;
            sortArr.push(item);
        });

        switch (dir) {
            case "up":
                sortArr.push("-"+fld);
                $lnk.data("sortdir","down");
                $sortUp.hide();
                $sortDown.show();
                $sortDefault.hide();
                break;
            case "down":
                $lnk.data("sortdir",null);

                $sortUp.hide();
                $sortDown.hide();
                $sortDefault.show();
                break;
            default:
                $lnk.data("sortdir","up");
                sortArr.push(fld);

                $sortUp.show();
                $sortDown.hide();
                $sortDefault.hide();
        }

        let nxtSort = sortArr.join(",");
        if(sort!==nxtSort) {
            inst.url.parameters.sort = nxtSort;
            if(!doNotLoad) {
                inst.loadFromRemote();
            }
        }
    }

    /**
     *
     * @param options
     * @returns {{template: null, view: null, total: null, offset: number, navtype: string, pageSize: number, paging: null, url: null}}
     */
    function createCollectionInstance(el,options)
    {
        // extract template
        // set default to innerHTML
        if(apiatorDebug) console.log("Create collection instance",options);

        let templateTxt = el.length ? el.html() : null;

        // console.log(templateTxt);
        if(options.template) {
            if(options.template instanceof jQuery) {
                if(apiatorDebug) console.log("template is JQuery object",options.template,el);
                let $tpl = options.template.clone().removeAttr("id");
                templateTxt = $("<div>").append($tpl).html();
            }
            else if(typeof options.template==="string" ) {
                if(apiatorDebug) console.log("template is raw text: can be eithe a JQuery selector or raw HTML",options.template,el);
                templateTxt = $("<div>").append($(options.template).clone().removeAttr("id")).html();
            }
        }


        if(templateTxt!==null) {
            templateTxt = templateTxt
                .replace(/&lt;/gi, '<')
                .replace(/&gt;/gi, ">")
                .replace(/&apos;/gi, "'")
                .replace(/&quot;/gi, '"')
                .replace(/&nbsp;/gi, " ")
                .replace(/&amp;/gi, "&");
            // if(apiatorDebug) console.log("Template txt",templateTxt);

            options.template = template(templateTxt);
        }

        let collectionConfig = {
            el: el,
            itemsContainer: options.hasOwnProperty("container") ? $(options.container) : el,
            allowempty: options.disableempty!==true
        };


        options.view = CollectionView(collectionConfig);

        let instance = Collection(options);

        // setup paging
        if (options.hasOwnProperty("paging") && $(options.paging).length) {
            instance.paging = Paging(options.paging, options,instance);
        }


        // setup sort
        if(options.hasOwnProperty("sort") && $(options.sort).length) {
            let $sort = $(options.sort);
            let sortFldsArr = instance.url && instance.url.parameters.sort ? instance.url.parameters.sort.split(",") : [];

            let sortFlds = {};
            sortFldsArr.forEach(function (item) {
                if(item[0]==="-") {
                    sortFlds[item.substr(1)] = "down";
                }
                sortFlds[item.substr(1)] = "up";
            });

            $sort.find("[data-sortfld]").each(function() {
                $(this).find(".sort-up").hide();
                $(this).find(".sort-down").hide();
                $(this).find(".sort-default").show();

                console.log(this,instance)
                $(this).data("instance",instance)
                    .on("click",function (event) {
                        sortNow($(event.currentTarget));
                    });

                if(typeof  sortFlds[$(this).data("sortfld")]!=="undefined") {
                    sortNow($(this),sortFlds[$(this).data("sortfld")]);
                }
            });
        }

        // setup filtering
        if (options.hasOwnProperty("filter") && $(options.filter).length && $(options.filter).prop("tagName")==="FORM") {
            instance.filtering = Filtering(options.filter, instance)
        }

        
        return instance;
    }

    /**
     *
     * @param options
     * @returns {{relationships: null, view: null, attributes: null, id: null, collection: null, type: null, url: null}}
     */
    function createItemInstance(el,options)
    {
        // let container = options.hasOwnProperty("container") ? $(options.container) : this;

        // extract template
        options.template = null;
        if(el.length) {
            let templateTxt = el[0].outerHTML
                .replace(/&lt;/gi, '<')
                .replace(/&gt;/gi, ">")
                .replace(/&apos;/gi, "'")
                .replace(/&quot;/gi, '"')
                .replace(/&nbsp;/gi, " ")
                .replace(/&amp;/gi, "&");
            options.template = template(templateTxt);
        }
        // options.template = template(templateTxt);

        return Item(options).bindView(ItemView({
            template: options.template,
            el: el,
            id: $(el).attr("id")?$(el).attr("id"):uid()
        }));
    }


    /**
     *
     * @param filterForm
     * @param collection
     * @constructor
     */
    function Filtering(filterForm,collection)
    {
        // console.log("Filtering",filterForm,collection);
        // normalize filterFrom to jquery object
        filterForm = $(filterForm);
        let _self = {
            collection: collection,
            el: filterForm
        };

        filterForm
            .data("instance",collection)
            .on("submit",function (e) {
                if(apiatorDebug) console.log("Filter form was submited");
                e.preventDefault();
                let filter = [];
                let frm = filterForm[0];
                for(let i=0; i<frm.elements.length;i++) {
                    let el = frm.elements[i];
                    let $el = $(el);
                    if(el.name && $el.val()) {
                        filter.push(
                            el.name + ($el.data("operator") ? $el.data("operator") : "=") + $el.val()
                        );
                    }
                }
                _self.collection.offset = 0;
                if(filter.length) {
                    _self.collection.url.parameters.filter = filter.join(",");
                }
                else {
                    delete _self.collection.url.parameters.filter;
                }
                _self.collection.loadFromRemote();
            })
            .on("reset",function () {
                delete _self.collection.url.parameters.filter;
                // _self.collection.url.parameters["page["+_self.collection.type+"][offset]"] = 0;
                _self.collection.loadFromRemote();
                if(apiatorDebug) console.log("filter form reset");
            });
        return filterForm;
    }

    /**
     *
     * @param pagingEl
     * @param collection
     * @returns {{el: (jQuery.fn.init|jQuery|HTMLElement), collection: *}}
     * @constructor
     */
    function Paging(pagingEl,options,collection)
    {
        
        let _paging = {
            collection: collection,
            el: $(pagingEl),
        };
        console.log("Paging",pagingEl,_paging,options.pagesizeinp  );
        let iniOffset = (_paging.collection.offset ? _paging.collection.offset : 0)*1;

        _paging.collection.paging = _paging;

        let defaultPageSize = 20;

        let $pageSizeInp = $(options.pagesizeinp);
        if($pageSizeInp.length) {
            _paging.collection.setPageSize($pageSizeInp.val());
            $pageSizeInp.off("change").on("change",function () {
                if(_paging.collection.setPageSize($pageSizeInp.val())) {
                    _paging.collection.loadFromRemote();
                }

            });
        }
        let pageSize = _paging.collection.pageSize;

        let $offsetInp = $(_paging.collection.offsetinp);
        if($offsetInp.length) {
            _paging.collection.setOffset($offsetInp.val());
            $offsetInp.off("change").on("change",function () {
                if(_paging.collection.setOffset($offsetInp.val())) {
                    _paging.collection.loadFromRemote();
                }
            });
        }

        let buttons = {
            page: _paging.el.find("[name=page]").remove(),
            prev: _paging.el.find("[name=prev]").remove(true),
            next: _paging.el.find("[name=next]").remove(true),
            first: _paging.el.find("[name=first]").remove(true),
            last: _paging.el.find("[name=last]").remove(true),
        };

        let $totalCount =  $(options.totalrecscount);
        console.log("Paging totalCount",$totalCount);

        _paging.el.empty();

        _paging.el.find("[data-type=pages]").empty();

        _paging.render = function () {
            console.log("Paging render",_paging);

            let pagesToShow = 5;

            let total = _paging.collection.total;
            if($totalCount.length) {
                if($totalCount[0].tagName==="INPUT") {
                    $totalCount.val(total);
                }
                else {
                    $totalCount.text(total);
                }
            }
            _paging.el.empty();

            iniOffset = _paging.collection.offset*1;


            if(_paging.collection.pageSize) {
                pageSize = _paging.collection.pageSize;
            }
            else if(total-iniOffset-_paging.collection.items.length>0) {
                pageSize = _paging.collection.items.length;
            }
            else {
                pageSize = defaultPageSize;
            }

            pageSize = pageSize*1;
            if(pageSize>total) {
                return;
            }

            let first = buttons.first.clone(true).attr("title", 0);
            let prev = buttons.prev.clone(true).attr("title", iniOffset - pageSize);

            if(iniOffset>0) {
                first.on("click", function () {
                    // _paging.collection.url.parameters["page["+_paging.collection.type+"][offset]"] = 0;
                    _paging.collection.setOffset(0);
                    _paging.collection.loadFromRemote();
                }).appendTo(_paging.el);

                prev.on("click", function () {
                    // _paging.collection.url.parameters["page["+_paging.collection.type+"][offset]"] = iniOffset - pageSize;
                    _paging.collection.setOffset(iniOffset-pageSize);
                    _paging.collection.loadFromRemote();
                }).appendTo(_paging.el);
            }

            let lowerLimit = iniOffset / pageSize - Math.floor(pagesToShow/2);
            lowerLimit = lowerLimit<0 ? 0 : lowerLimit;

            let upperLimit = iniOffset / pageSize + Math.ceil(pagesToShow/2);
            upperLimit = upperLimit*pageSize<total ? upperLimit : Math.ceil(total/pageSize);

            for(let i=lowerLimit;i<upperLimit;i++) {

                let page = buttons.page.clone(true).text(i+1).on("click", function () {
                    _paging.collection.setOffset(i*pageSize);
                    // _paging.collection.url.parameters["page["+_paging.collection.type+"][offset]"] = i*pageSize;
                    _paging.collection.loadFromRemote();
                }).attr("title", i*pageSize).appendTo(_paging.el);

                if(iniOffset/pageSize===i)
                    page.addClass("active").off("click");
            }

            let nxtOffset = iniOffset + pageSize;
            let next = buttons.next.clone(true).attr("title", nxtOffset);

            let lastPageOffset = (Math.ceil(total/pageSize)-1)*pageSize;
            let last = buttons.last.clone(true).attr("title", lastPageOffset);
            if(iniOffset + pageSize <= total) {
                next.appendTo(_paging.el).on("click", function () {
                    _paging.collection.setOffset(iniOffset+pageSize);
                    // _paging.collection.url.parameters["page["+_paging.collection.type+"][offset]"] = iniOffset+pageSize;
                    _paging.collection.loadFromRemote();
                });

                last.appendTo(_paging.el).on("click", function () {
                    // _paging.collection.url.parameters["page["+_paging.collection.type+"][offset]"] = lastPageOffset;
                    _paging.collection.setOffset(lastPageOffset);

                    _paging.collection.loadFromRemote();
                });
            }
            $(_paging.collection.offsetinp).val(iniOffset);

        };

        return _paging;
    }

    /**
     *
     * @param options
     * @constructor
     */
    function Storage(options)
    {

        let defaultOptions = {
            url: null,
            method: "GET"
        };

        options = parseOptions(options);

        Object.assign(defaultOptions, options);

        let _storage = {};

        /**
         *
         * @param options
         * @returns {Promise<unknown>}
         */
        _storage.sync = function (options) {
            if($.fn.apiator.baseUrl){
                options.url = $.fn.apiator.baseUrl + options.url;
            }
            options = Object.assign(
                Object.assign({},defaultOptions),
                parseOptions(options)
            );

            if (!options.hasOwnProperty("url")) {
                throw "No URL provided";
            }

            return new Promise(function (resolve,reject) {
                $.ajax(options)
                    .done(function (data, textStatus, jqXHR) {
                        resolve( {
                            data: data,
                            textStatus: textStatus,
                            jqXHR: jqXHR
                        });
                    })
                    .fail(function (jqXHR, textStatus, errorThrown) {
                        reject( {
                            options: options,
                            jqXHR: jqXHR,
                            textStatus: textStatus,
                            errorThrown: errorThrown
                        });
                    });
            });
        };

        /**
         *
         * @param ctx
         * @param url
         * @param opts
         * @param data
         * @returns {Promise<unknown>}
         */
        _storage.create = function (ctx, url, opts, data) {
            let options = {
                context: ctx,
                url: url,
                method: "POST",
                data: data
            };
            Object.assign(options, opts);
            return _storage.sync(options);
        };

        /**
         *
         * @param ctx
         * @param url
         * @param opts
         * @returns {Promise<unknown>}
         */
        _storage.read = function (ctx, url, opts) {
            let options = {
                context: ctx,
                url: url,
                method: "GET"
            };
            Object.assign(options, opts);

            return _storage.sync(options);
        };

        /**
         *
         * @param ctx
         * @param url
         * @param opts
         * @returns {Promise<unknown>}
         */
        _storage.delete = function (ctx, url, opts) {
            let options = {
                context: ctx,
                url: url,
                method: "DELETE"
            };
            Object.assign(options, opts);

            return _storage.sync(options);
        };

        /**
         *
         * @param ctx
         * @param url
         * @param opts
         * @param data
         * @returns {Promise<unknown>}
         */
        _storage.update = function (ctx, url, opts, data) {
            let options = {
                context: ctx,
                url: url,
                method: "PATCH",
                contentType: "application/vnd.api+json",
                data: data
            };
            Object.assign(options, opts);

            return _storage.sync(options);

        };

        return _storage;
    }

    function uid () {
        // Math.random should be unique because of its seeding algorithm.
        // Convert it to base 36 (numbers + letters), and grab the first 9 characters
        // after the decimal.
        return "uid_" + Math.random().toString(36).substr(2, 9);
    }
   

    $.fn.apiator2collection = function(opts) {
        let options = {
            resourcetype: "collection"
        };

        if(typeof opts==="undefined")
            opts = {};
        if(typeof opts==="string") {
            opts = {
                url: opts,
            }
        }
        opts = Object.assign(opts,options);
        return this.apiator2(opts);
    };

    $.fn.apiator2item = function(opts) {
        let options = {
            resourcetype: "item"
        };

        if(typeof opts==="undefined")
            opts = {};
        if(typeof opts==="string") {
            opts = {
                url: opts,
            }
        }

        opts = Object.assign(opts,options);
        return this.apiator2(opts);
    };



    $.fn.apiator2 = function (opts) {

        if(typeof opts==="undefined")
            opts = {};

        if(typeof opts==="string")
            opts = {
                url: opts,
            };

        if(opts.type==="undefined")
            opts.type="collection";

        if(opts.resourcetype==="collection" && opts.url)
            opts.type = opts.url.split("/").pop().split("?")[0].split("#")[0];


        if(typeof dbApiBaseUrl!=="undefined" && typeof opts.url!=="undefined")
            opts.url = dbApiBaseUrl + opts.url;

        opts.returninstance = true;
        opts.dontload = true;
        return this.apiator(opts);
    }
})($);

class Apiator {
    constructor(url) {

    }

}
class ApiatorCollection {
    constructor(url,node){
        $(node).apiator2collection(url)
    }
}

class ApiatorItem {
    constructor(){

    }
}



