var tq = null
var swreg = null
var gcal = null
var todo = null

document.addEventListener('DOMContentLoaded', function() {
    tq = run()
    todo = todos()
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/tfq/sw.js').then(function(registration) {
            swreg = registration
            tq.debug_ntf('sw reg')
            console.log('Service worker registration succeeded:', registration);
        }).catch(function(error) {
            tq.debug_ntf('sw reg fail')
            console.log('Service worker registration failed:', error);
        });
    } else {
        tq.debug_ntf('no sw')
        console.log('Service workers are not supported.');
    }
});

function run() {
    let TRACE = (window.location.search.length > 3 && window.location.search.substring(0, 4) == '?err')
    let web_worker = null
    let centerNow = 0
    let hideAfterMs = 1000 * 60 * 60 * 24 * 365 // 1 year
    let selProps = null // editframe and cutframe depend on the currently selected item 
    const EMD_SOUND = document.getElementById('aud_start')
    const START_SOUND = document.getElementById('aud_end')
    const POINT_SOUND = document.getElementById('aud_point')
    const LS_KEY = 'all-time-frames'
    const SKIP_NOTIF_IF_OLDER_THAN_MS = 1000 * 60 * 10 //10 min
    const NOTIFICATION_CLOSE_AFTER = 6000 // 6sec
    let draggedtime = new Date()
    let lockbtn = document.getElementById('lockbtn')

    // returns either the selected frame or draggedtime or NOW + 1 min
    function get_append_date() {
        if (selProps && selProps.items && selProps.items.length > 0) {
            let frame = items.get(selProps.items[0])
            if (frame) return new Date(frame.end)
        }

        if (!draggedtime) {
            let n = new Date()
            return new Date(n.setMinutes(n.getMinutes() + 1))
        } else return draggedtime
    }

    function getTimeFrameId() {
        return new Date().getTime()
    }

    function goto_spec_end() {
        let gotomoment = moment(endDatePicker.value + " " + endTimePicker.value)
        let gt = gotomoment.toDate()
        if (gt && !isNaN(gt.getTime())) {
            draggedtime = gt
            setDateToInputs(startDatePicker, startTimePicker, gt)
            timeline.setCustomTime(gt)
            timeline.moveTo(gt)
        }
    }

    function gotonow() {
        timeline.moveTo(new Date())
    }

    function gotolast() {
        let n = new Date()
        if (items) {
            for (let i of items.get()) {
                let ed = new Date(i.end)
                if (ed > n) n = ed
            }
        }

        timeline.moveTo(n)
        timeline.setCustomTime(n)
        draggedtime = n
    }

    const SOUND_TYPE = { START: 1, END: 2, POINT: 3 }

    function notify(text, soundtype = 1) {
        try {
            let sound = ''
            let title = ''
            if (soundtype == SOUND_TYPE.START) {
                sound = START_SOUND
                title = 'In time frame'
            } else if (soundtype == SOUND_TYPE.END) {
                sound = EMD_SOUND
                title = 'Out of time frame'
            } else if (soundtype == SOUND_TYPE.POINT) {
                sound = POINT_SOUND
                title = 'Time point'
            }
            let ntfArgs = {
                body: text,
                icon: 'timer.png',
                badge: 'icons/new.png'
            }

            let granted = () => {
                try {
                    if (swreg) {
                        debug_ntf('swreg.showNotification')
                        swreg.showNotification(title, ntfArgs)
                    } else {
                        debug_ntf('new Notification')
                        let n = new Notification(title, ntfArgs)
                        setTimeout(() => { n.close() }, NOTIFICATION_CLOSE_AFTER);
                    }
                    if (sound) sound.play()
                } catch (ex) { debug_ntf('ex in granted: ' + ex) }
            }

            if ("Notification" in window) {
                if (Notification.permission === "granted") granted()
                else if (Notification.permission !== 'denied') {
                    Notification.requestPermission().then(function(result) {
                        if (result === "granted") granted()
                    })
                }
            }
        } catch (ex) {}
    }

    function add() {
        let tIdGen = getTimeFrameId()
        let now = new Date()
        let name = prompt(`Time frame name: \n --mm sets a duration in minutes, default is 60 \n select a frame to append `)
        if (!name) return
        let defMin = 60
        let hasmin = name.indexOf(' --') // duration in min

        if (hasmin > 0) {
            defMin = parseInt(name.substring(hasmin + 3))
            if (isNaN(defMin)) { return 60 }
            if (defMin < 0 || defMin > 9999) defMin = 60
            name = name.substring(0, hasmin)
        }

        let dd = datediff({ start: new Date(), end: new Date().setMinutes(now.getMinutes() + defMin) })
        let initlabel = `${dd.h}h:${dd.m}m`
        let startTime = get_append_date()
        if (name) {
            let endTime = new Date(startTime).setMinutes(startTime.getMinutes() + defMin)
            let c = `<div id="tfh-${tIdGen}"><b class="tf-text" >${name}</b><span id="tf-${tIdGen}" class="time-frame">${initlabel}</span></div>`
            let tframe = {
                id: tIdGen,
                name: name,
                content: c,
                start: startTime,
                end: endTime,
                isendnotified: 0,
                isstartnotified: 0
                    // type: 'range'
            }
            items.add(tframe)
        }
    }

    function create(name, dates, props) {
        if (!name) name = prompt('Frame label:')
        if (!name) return
        let tIdGen = props && props.id ? props.id : getTimeFrameId()
        if (!dates) dates = getDatesFromInputs()
        if (!dates || isNaN(dates[0].getTime()) || isNaN(dates[1].getTime())) {
            ntf('The dates are incorrect.', 'ntf-fail')
            return
        }
        if (name) {
            let dd = datediff({ start: dates[0], end: dates[1] })
            let initlabel = `${dd.h}h:${dd.m}m`
            let c = `<div id="tfh-${tIdGen}"><b class="tf-text" >${name}</b><span id="tf-${tIdGen}" class="time-frame">${initlabel}</span></div>`
            let tframe = {
                id: tIdGen,
                name: name,
                content: c,
                start: dates[0],
                end: dates[1],
                isendnotified: 0,
                isstartnotified: 0
            }
            if (props)
                for (key of Object.keys(props))
                    tframe[key] = props[key]
            items.add(tframe)
        }
    }

    function create_point(name, enddate, props) {
        if (!name) name = prompt('Time point label:')
        if (!name) return
        let tIdGen = props && props.id ? props.id : getTimeFrameId()
        if (!enddate && draggedtime) enddate = new Date(draggedtime)
        if (!enddate || isNaN(enddate)) {
            ntf('The time point date (end date) is incorrect.', 'ntf-fail')
            return
        }
        if (name) {
            let c = `<div id="tfh-${tIdGen}"><b class="tf-text" >${name}</b></div>`
            let tframe = {
                id: tIdGen,
                name: name,
                content: c,
                start: enddate,
                end: enddate,
                isendnotified: 0,
                isstartnotified: 1,
                editable: { updateTime: true, updateGroup: false, remove: true },
                type: 'box',
                ispoint: 1
            }
            if (props)
                for (key of Object.keys(props))
                    tframe[key] = props[key]
            items.add(tframe)
        }
    }

    function save_to_ls(btn) {
        try {
            let All = []
            for (let i of items.get())
                if (!i.imported || i.imported < 1)
                    All.push(JSON.stringify(i))

            localStorage.setItem(LS_KEY, JSON.stringify(All))
            if (btn) btn.classList.add('b-ok')
            ntf('saved', 'ntf-ok')
        } catch (ex) {
            if (btn) btn.classList.add('b-fail')
            ntf('failed', 'ntf-fail')
        } finally {
            if (btn)
                setTimeout(function() {
                    btn.classList.remove('b-ok')
                    btn.classList.remove('b-fail')
                }, 800)
        }
    }

    function load_from_ls() {
        let allJson = localStorage.getItem(LS_KEY)
        return allJson ? JSON.parse(allJson) : null
    }

    function clear_ls(btn) {
        try {
            if (confirm('Delete all frames from the local storage?')) {
                localStorage.setItem(LS_KEY, '')
                items.clear()
                if (btn) btn.classList.add('b-ok')
                ntf('cleared', 'ntf-ok')
            }
        } catch (ex) {
            if (btn) btn.classList.add('b-fail')
            ntf('clear failed', 'ntf-ok')
        } finally {
            if (btn)
                setTimeout(function() {
                    btn.classList.remove('b-ok')
                    btn.classList.remove('b-fail')
                }, 800)
        }
    }

    function validate(frame) {
        if (!frame.start || !frame.end || !frame.name || !frame.content)
            return false
        return true
    }

    let merged_items = 0

    function merge(frames) {
        if (frames)
            for (let f of frames) {
                f.start = new Date(f.start)
                f.end = new Date(f.end)
                if (validate(f))
                    if (f.id) {
                        if (items.get(f.id) == null) {
                            if (f.ispoint > 0) create_point(f.name, f.end, { id: f.id })
                            else create(f.name, [f.start, f.end], { id: f.id })
                            merged_items++
                        }
                    }
            }
    }

    function clear() {
        items.clear()
    }

    function datediff(item, endtime) {
        let r = { d: 0, h: 0, m: 0, s: 0 }
        let end = moment(endtime ? endtime : item.end)
        let start = moment(item.start)
        let duration = moment.duration(end.diff(start));
        // r.d = duration.asDays()
        r.h = Math.floor(duration.asHours())
        r.m = Math.floor(duration.asMinutes())
        if (r.h > 0) r.m -= r.h * 60
            // r.s = duration.asSeconds()
        return r
    }

    let startDatePicker = document.getElementById('startDatePicker')
    let endDatePicker = document.getElementById('endDatePicker')
    let startTimePicker = document.getElementById('startTimePicker')
    let endTimePicker = document.getElementById('endTimePicker')
    let container = document.getElementById('visualization');
    let now = new Date()
    var items = new vis.DataSet([]);

    let saved = load_from_ls()
    if (saved && saved.length > 0) {
        for (let si of saved) {
            let tf = JSON.parse(si)
            if (tf) {
                if (tf.start) tf.start = new Date(tf.start)
                if (tf.end) tf.end = new Date(tf.end)
                items.add(tf)
            }
        }
    }

    var options = {
        orientation: 'top',
        start: new Date(now).setDate(now.getHours() - 2),
        end: new Date(now).setDate(now.getHours() + 2),
        zoomMin: 1000 * 20,
        zoomMax: 1000 * 60 * 60 * 24 * 31 * 2, // 2 months in milliseconds
        height: '100%',
        margin: { axis: 30, item: { vertical: 4, horizontal: -0.5 } },
        multiselect: true,
        editable: {
            add: false,
            updateTime: true,
            updateGroup: true,
            remove: true,
        },
        showCurrentTime: true,
        onAdd: function(item, callback) {
            item.content = prompt('Edit items text:', item.content);
            if (item.content != null) {
                callback(item); // send back adjusted item
            } else {
                callback(null); // cancel updating the item
            }
        },
        onRemove: function(item, callback) {
            if (confirm('Delete ' + item.name)) {
                callback(item)
            }
        },
        onMoving: function(item, callback) {
            if (item.ispoint) {
                callback(item)
            } else {
                let tf = document.getElementById('tf-' + item.id)
                if (tf) {
                    let diff = datediff(item)
                    tf.innerText = `${diff.h}h:${diff.m}m`
                    let s = new Date(item.start)
                    let e = new Date(item.end)
                    setDateToInputs(startDatePicker, startTimePicker, s)
                    setDateToInputs(endDatePicker, endTimePicker, e)
                    callback(item)
                } else callback(null)
            }
        },
        onMove: function (item, callback) {
            callback(item)
            let tf = document.getElementById('tf-' + item.id)
            if (tf) items.update({ id: item.id, content: tf.parentElement.outerHTML })
        }
    };

    let timeline = null;

    function create_timeline() {
        container.innerHTML = ''
        timeline = new vis.Timeline(container, items, options)

        timeline.addCustomTime(new Date())

        timeline.on('timechange', function(event) {
            draggedtime = new Date(event.time)
        });

        timeline.on('select', function(d) {
            if (TRACE) console.log(d);
            selProps = d
            if (d && d.items && d.items.length > 0) {
                let frame = items.get(selProps.items[0])
                if (frame) {
                    let s = new Date(frame.start)
                    let e = new Date(frame.end)
                    setDateToInputs(startDatePicker, startTimePicker, s)
                    setDateToInputs(endDatePicker, endTimePicker, e)
                    updatelockbtn(frame)
                }
            }
        });

    }

    create_timeline();

    setDateToInputs(startDatePicker, startTimePicker, new Date())
    setDateToInputs(endDatePicker, endTimePicker, new Date())

    function updatelockbtn(frame) {
        if (frame) {
            if (!frame.editable) lockbtn.innerText = 'lock'
            else lockbtn.innerText = frame.editable.updateTime === true ? 'lock' : 'unlock'
        }
    }

    function setDateToInputs(inputDate, inputTime, date) {
        if (date) {
            let m = moment(date)
            if (inputDate) inputDate.value = m.format('YYYY-MM-DD')
            if (inputTime) inputTime.value = m.format('HH:mm')
        }
    }

    function getDatesFromInputs() {
        let sdt = moment(startDatePicker.value + " " + startTimePicker.value)
        let edt = moment(endDatePicker.value + " " + endTimePicker.value)
        let r = []
        if (sdt) r.push(sdt.toDate())
        if (edt) r.push(edt.toDate())
        if (sdt >= edt) {
            ntf('The time-frame duration is negative', 'ntf-fail', 5000)
            return null
        }
        return r
    }

    function update_dates() {
        if (selProps && selProps.items && selProps.items.length > 0) {
            let frame = items.get(selProps.items[0])
            if (frame) {
                let dates = getDatesFromInputs()
                if (dates && dates.length > 0) {
                    let upd = { id: selProps.items[0] }
                    if (dates[0]) upd.start = dates[0]
                    if (dates[1]) upd.end = dates[1]
                    let t = document.getElementById(`tfh-${selProps.items[0]}`)
                    let tf = document.getElementById('tf-' + frame.id)
                    if (t && tf) {
                        let diff = datediff(upd)
                        tf.innerText = `${diff.h}h:${diff.m}m`
                        upd.content = t.outerHTML
                    }
                    items.update(upd)
                    ntf('updated', 'ntf-ok')
                }
            }
        }

    }


    function editframe() {
        if (selProps.items && selProps.items.length > 0) {
            let t = document.getElementById(`tfh-${selProps.items[0]}`)
            if (t) {
                let b = t.querySelectorAll(`.tf-text`)
                if (b.length > 0) {
                    let text = prompt('Edit text', b[0].innerHTML)
                    b[0].innerHTML = text
                    items.update({ id: selProps.items[0], content: t.outerHTML })
                }
            }
        }
    }


    function cutframe() {
        if (selProps.items && selProps.items.length > 0) {
            let t = document.getElementById(`tfh-${selProps.items[0]}`)
            let frame = items.get(selProps.items[0])
            if (t && frame) {
                let s = new Date(frame.start)
                let e = new Date(frame.end)
                let n = new Date()
                if (s < n && n < e) {
                    let b = t.querySelectorAll(`.tf-text`)
                    if (b.length > 0 && confirm(`Cut ${b[0].innerText}?`)) {
                        let tf = t.querySelectorAll(`[id='tf-${frame.id}']`) // the span with the time
                        if (tf.length > 0) {
                            let diff = datediff(frame, n)
                            tf[0].innerText = `${diff.h}h:${diff.m}m`
                        }
                        items.update({ id: selProps.items[0], end: n, content: t.outerHTML })
                    }
                }
            }
        }
    }

    gotonow()

    // there is no real use of the web worker, 
    // all browsers will kill the ticker when 
    // the page is not active
    function start_web_workwer() {
        if (typeof(Worker) !== "undefined") {
            web_worker = new Worker("bw.js");
            web_worker.onmessage = function(e) {
                tick();
            };
        } else { window.alert("I need web workers."); }
    }

    start_web_workwer()

    // main ticker
    function tick() {
        for (let x of tq.items.get()) {
            if (x.isendnotified < 1) {
                let now = Date.now()
                let xstart = new Date(x.start).valueOf()
                let xend = new Date(x.end).valueOf()
                if (xend < now) {
                    let stype = x.ispoint ? SOUND_TYPE.POINT : SOUND_TYPE.END
                    if (now - xend < SKIP_NOTIF_IF_OLDER_THAN_MS) notify(x.name, stype)
                    items.update({ id: x.id, isendnotified: 1, className: 'past locked', editable: { updateTime: false, updateGroup: false, remove: true } })
                    if (merged_items < 1) save_to_ls() // otherwise it will save the whole list for all imported passed items
                } else {
                    if (now > xstart && now < xend && x.isstartnotified < 1) {
                        if (now - xstart < SKIP_NOTIF_IF_OLDER_THAN_MS) notify(x.name, SOUND_TYPE.START)
                        let css = !x.imported || x.imported < 1 ? 'active' : 'imported'
                        if (x.editable && x.editable.updateTime === false) css += ' locked'
                        items.update({ id: x.id, isstartnotified: 1, className: css })
                        if (merged_items < 1) save_to_ls()
                    } else if (xstart > now) {
                        let css = !x.imported || x.imported < 1 ? '' : 'imported'
                        if (x.editable && x.editable.updateTime === false) css += ' locked'
                        items.update({ id: x.id, isstartnotified: 0, className: css })
                    }
                }
            } else if (Date.now() - x.end > hideAfterMs) {
                items.remove(x.id)
            }
        }
        if (merged_items > 0) merged_items = 0
        if (centerNow > 0) gotonow()
    }

    function track(btn) {
        btn.classList.toggle('toggle')
        centerNow = centerNow == 1 ? 0 : 1;
    }

    // zoom
    for (let i = 0; i < 4; i++)
        setTimeout(function() {
            timeline.zoomIn(1)
        }, i * 500)

    //center
    setTimeout(function() { gotonow() }, 2100)

    document.addEventListener("keypress", function(e) {
        if (e && e.key == '+') add()
    });


    function info() {
        let i = document.getElementById('info')
        i.classList.toggle('hidden')
    }

    function toggle_set_dates() {
        let i = document.getElementById('dateTimePickers')
        i.classList.toggle('hidden')
    }

    function lockframe() {
        if (selProps && selProps.items && selProps.items.length > 0) {
            let frame = items.get(selProps.items[0])
            if (frame) {
                if (frame.imported) {
                    ntf('Cannot modify imported frames', 'ntf-fail', 4000)
                    return
                }
                if (frame.editable && frame.editable.updateTime != null) {
                    frame.editable.updateTime = !frame.editable.updateTime
                    togglecss(frame, 'locked', frame.editable.updateTime ? 0 : 1)
                } else {
                    frame.editable = { updateTime: false, remove: true }
                    togglecss(frame, 'locked', 1)
                }
                items.update(frame)
                updatelockbtn(frame)
                    // let text = frame.editable.updateTime === true ? 'unlocked' : 'locked'
                    // ntf('frame ' + text, 'ntf-ok')
            }
        }
    }

    function togglecss(item, css, add = 1) {
        if (item) {
            if (add > 0) {
                if (item.className.indexOf(css) < 0) item.className += ' ' + css
            } else item.className = item.className.replace(css, '')
        }
    }

    let ntfdiv = document.getElementById('ntf')

    function debug_ntf(text, css = 'ntf-debug', dur = 30000) {
        if (TRACE) {
            ntf(text, css, dur)
        }
    }

    function ntf(text, css, dur = 1000) {
        let newntf = document.createElement('div')
        newntf.innerHTML = text
        newntf.classList.add(css)
        newntf.classList.add('newntf')
        ntfdiv.appendChild(newntf)
        newntf.onclick = () => { newntf.remove() }
        setTimeout(function() {
            try {
                ntfdiv.removeChild(newntf)
            } catch (x) {}
        }, dur)
    }

    function hide_time(dates) {
        if (!dates) dates = getDatesFromInputs()
        if (dates && dates.length > 1) {
            if (isNaN(dates[0]) || isNaN(dates[1])) { ntf('Invalid dates.', 'ntf-fail'); return }
            options.hiddenDates = [{
                start: dates[0],
                end: dates[1],
                repeat: 'daily'
            }]
            create_timeline()
            gotonow()
        }
    }

    function hide_07() {
        let n = new Date()
        let e = new Date()
        n.setHours(0, 0, 0, 0)
        e.setHours(7, 0, 0, 0)
        hide_time([n, e])
    }

    function hide_19_8() {
        let s = new Date()
        let e = new Date()
        s.setHours(19, 0, 0, 0)
        e.setDate(e.getDate() + 1)
        e.setHours(8, 0, 0, 0)
        hide_time([s, e])
    }

    let tbm = document.getElementById('toolbar-more')
    let mi = document.getElementById('moreimg')

    function more() {
        tbm.classList.toggle('hidden')
        mi.src = tbm.classList.contains('hidden') ?
            'icons/more.png' : 'icons/morev.png'
    }

    gcal = new gooc()

    return {
        LS_KEY,
        create,
        create_point,
        add,
        merge,
        toggle_set_dates,
        update_dates,
        gotonow,
        gotolast,
        timeline,
        clear,
        items,
        track,
        save_to_ls,
        load_from_ls,
        clear_ls,
        zoomin: function() { timeline.zoomIn(1) },
        zoomout: function() { timeline.zoomOut(1) },
        getDatesFromInputs,
        editframe,
        cutframe,
        lockframe,
        info,
        ntf,
        debug_ntf,
        hide_time,
        hide_07,
        hide_19_8,
        goto_spec_end,
        more
    }
}

function gooc() {
    function registerjs() {
        let scr = document.getElementById('goog')
        if (!scr) {
            src = document.createElement('script')
            src.id = 'goog'
            src.onload = function() {
                if (gcal) gcal.handleClientLoad()
            }
        }
        src.setAttribute('defer', '')
        src.setAttribute('src', 'https://apis.google.com/js/api.js')
        document.head.appendChild(src)
    }

    registerjs()

    const CLIENT_ID = '189775219070-f43ndgfe1sjakmp3q065000ek8tq4f27.apps.googleusercontent.com';
    const API_KEY = 'AIzaSyDjDM4STm3EEz2Q78L2c4RQerlzTcjh604';
    const DISCOVERY_DOCS = [
        "https://www.googleapis.com/discovery/v1/apis/calendar/v3/rest",
        'https://www.googleapis.com/discovery/v1/apis/drive/v3/rest'
    ];
    const SCOPES = 'https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/drive.file'
    const DRIVE_URL = 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart'
    const UPDATE_DRIVE_URL = 'https://www.googleapis.com/upload/drive/v3/files/'
    const BOUNDARY = '***';
    const DRIVE_FILE_NAME = 'tfq-frames-data.json'
    let user = null
    let oauthToken = null
    let drive_file_id = ''
    let drive_file = null

    let authorizeButton = document.getElementById('authorize-button')
    let signoutButton = document.getElementById('signout-button')
    let mergeButton = document.getElementById('merge-with-google')
    let fromgooglecalendar = document.getElementById('from-google-calendar')
    let overridegoogle = document.getElementById('override-google')

    function handleClientLoad() {
        tq.debug_ntf('goog loaded')
        gapi.load('client:auth2', initClient);
    }

    function getdrivefile(drivefilename, clb, clberr) {
        return gapi.client.drive.files.list({
            'q': `name='${drivefilename}' and trashed = false`,
            'orderBy': 'modifiedByMeTime desc'
        }).then(function(response) {
            let files = response.result.files;
            if (files && files.length > 0) {
                gapi.client.drive.files.get({
                    'fileId': files[0].id,
                    'alt': 'media'
                }).then(function(resp) {
                    try {
                        if (resp) clb({ fileid: files[0].id, result: resp.result })
                    } catch (err) { console.log(err) }
                }).catch((er) => {
                    console.log('Failed to load the ' + drivefilename + ' /  ' + er)
                    if (clberr) clberr(er)
                })
            } else clb()
        });
    }

    function updatedrive(upload = 0, data, drivefileid, drivefilename, clb, clbfail) {
        if (oauthToken && data) {
            let updatebody = JSON.stringify(data)
            let body = [,
                '--' + BOUNDARY,
                'Content-Type: application/json; charset=UTF-8', ,
                JSON.stringify({
                    'name': drivefilename,
                    'title': drivefilename,
                    'mimeType': 'application/json'
                }), ,
                '--' + BOUNDARY,
                'Content-Type: application/json', ,
                JSON.stringify(data), ,
                '--' + BOUNDARY + '--'
            ].join('\n')
            fetch(upload > 0 ? DRIVE_URL : UPDATE_DRIVE_URL + drivefileid + '?uploadType=media', {
                method: upload > 0 ? 'POST' : 'PATCH',
                headers: new Headers({
                    'Authorization': 'Bearer ' + oauthToken,
                    'Content-Type': 'multipart/related; boundary=' + BOUNDARY,
                    'Content-Length': upload > 0 ? body.length : updatebody.length
                }),
                body: upload > 0 ? body : updatebody
            }).then(function(d) {
                if (d && clb) clb(d)
            }).catch(function(d) {
                if (clbfail) clbfail()
            });
        }
    }

    function initClient() {
        gapi.client.init({
            apiKey: API_KEY,
            clientId: CLIENT_ID,
            discoveryDocs: DISCOVERY_DOCS,
            scope: SCOPES
        }).then(function() {
            authorizeButton.onclick = () => gapi.auth2.getAuthInstance().signIn().then(() => {
                user = gapi.auth2.getAuthInstance().currentUser.get()
                oauthToken = user.getAuthResponse().access_token
                updateSigninStatus(gapi.auth2.getAuthInstance().isSignedIn.get())
            })
            signoutButton.onclick = () => {
                let auth2 = gapi.auth2.getAuthInstance();
                auth2.signOut().then(() => {
                    gapi.auth2.getAuthInstance().disconnect()
                    let isin = gapi.auth2.getAuthInstance().isSignedIn.get()
                    console.log("in:" + isin)
                    updateSigninStatus(false) // because of auth2.disconnect()
                    tq.ntf('Calendar read permissions revoked', 'ntf-ok')
                })
            }
            fromgooglecalendar.onclick = function() {
                fromgooglecalendar.disabled = true
                listUpcomingEvents(100, () => { fromgooglecalendar.disabled = false })
            }
            mergeButton.onclick = function() {
                mergeButton.disabled = true
                merge_with_google_drive_file(() => { mergeButton.disabled = false })
            }
            overridegoogle.onclick = function() {
                overridegoogle.disabled = true
                upload_frames_to_drive(0, () => { overridegoogle.disabled = false })
            }
        });
    }

    function merge_with_google_drive_file(clb) {
        getdrivefile(DRIVE_FILE_NAME, (d) => {
            try {
                if (clb) clb()
                if (!d) return
                drive_file = d.result
                drive_file_id = d.fileid
                if (drive_file_id) {
                    if (drive_file) {
                        if (drive_file.frames) {
                            let All = new Map()
                            let frames = tq.items.get()
                            for (let f of frames)
                                All.set(f.id, f)
                            for (let pe of drive_file.frames)
                                All.set(pe.id, pe)
                            let R = []
                            for (let v of All.values())
                                R.push(JSON.stringify(v))
                            localStorage.setItem(tq.LS_KEY, JSON.stringify(R))
                        }
                        if (drive_file.todo) {
                            let s = localStorage.getItem(todo.LS_KEY)
                            let T = JSON.parse(s)
                            let All = new Map()
                            for (let t of T)
                                All.set(t.id, t)
                            for (let td of drive_file.todo)
                                All.set(td.id, td)
                            let R = []
                            for (let v of All.values())
                                R.push(v)
                            localStorage.setItem(todo.LS_KEY, JSON.stringify(R))
                        }
                        tq = run()
                        tq.ntf('The frames from your google drive are merged with the local data', 'ntf-ok', 6000)
                    }
                } else upload_frames_to_drive(1)
            } catch (ex) { console.log(ex) }
        }, (err) => {
            if (clb) clb()
            tq.ntf('Failed to load the ' + drivefilename, 'ntf-fail', 6000)
        })
    }

    function upload_frames_to_drive(createfile = 0, clb) {
        if (drive_file_id || createfile > 0) {
            let frames = tq.items.get()
            let todolist = localStorage.getItem(todo.LS_KEY)
            let data = {
                frames: frames,
                todo: todolist ? JSON.parse(todolist) : null
            }
            updatedrive(createfile, data, drive_file_id, DRIVE_FILE_NAME,
                () => {
                    if (clb) clb()
                    tq.ntf('Frames uploaded', 'ntf-ok')
                },
                () => {
                    if (clb) clb()
                    tq.ntf('Upload failed', 'ntf-fail')
                })
        } else tq.ntf('You have to merge with the drive data first.', 'ntf-fail', 7000)
    }

    function updateSigninStatus(isSignedIn) {
        if (isSignedIn) {
            authorizeButton.classList.add('hidden')
            signoutButton.classList.remove('hidden')
            fromgooglecalendar.classList.remove('hidden')
            overridegoogle.classList.remove('hidden')
            mergeButton.classList.remove('hidden')
        } else {
            authorizeButton.classList.remove('hidden')
            signoutButton.classList.add('hidden')
            fromgooglecalendar.classList.add('hidden')
            overridegoogle.classList.add('hidden')
            mergeButton.classList.add('hidden')
        }
    }

    function listUpcomingEvents(maxResults = 100, clb) {
        gapi.client.calendar.events.list({
            'calendarId': 'primary',
            'timeMin': (new Date()).toISOString(),
            'showDeleted': false,
            'singleEvents': true,
            'maxResults': maxResults,
            'orderBy': 'startTime'
        }).then(function(response) {
            let E = response.result.items;
            if (E.length > 0) {
                // remove all imported items before adding from google
                // because the id's will be different
                for (let gi of tq.items.get())
                    if (gi.imported)
                        tq.items.remove(gi.id)
                for (let i of E) {
                    if (i.start && i.start.dateTime && i.end && i.end.dateTime) {
                        let sd = new Date(i.start.dateTime)
                        let ed = new Date(i.end.dateTime)
                        let dates = [sd, ed]
                        let props = {
                            className: 'imported',
                            editable: { updateTime: false, remove: false },
                            imported: 1 //prevent saving
                        }
                        if (ed - sd > 60000) tq.create(i.summary, dates, props)
                        else {
                            props.ispoint = 1
                            tq.create_point(i.summary, sd, props)
                        }
                    }
                }
            } else tq.ntf('No upcoming events found.', 'ntf-ok', 2000)
            if (clb) clb()
        });
    }

    return {
        handleClientLoad,
        initClient,
        updateSigninStatus,
        listUpcomingEvents,
        getdrivefile,
        updatedrive,
        merge_with_google_drive_file,
        upload_frames_to_drive
    }
}

function todos() {
    const LS_KEY = "all_todo_items"
    const HOST_WRAPPER_ID = 'todowrp'
    const HOST_ID = "todo-list-host"
    const TODO_ITEM = "todo-item"
    const HEADER_CSS = 'todo-header'
    const HEADER_TITLE_CSS = 'todo-title'
    const DESC_CSS = 'todo-desc'
    const CE = 'contenteditable'
    const SELECTED_CSS = 'todo-selected'
    const HOST = document.getElementById(HOST_ID)

    if (HOST)
        HOST.onkeypress = function(e) {
            if (e.keyCode == '13') return false
        }

    function loadlist() {
        let s = localStorage.getItem(LS_KEY)
        let L = JSON.parse(s)
        if (L) {
            clear()
            for (let l of L)
                create_item(l)
        }
        return L
    }

    function merge(items) {
        let s = localStorage.getItem(LS_KEY)
        let L = JSON.parse(s)
        while (HOST.children.length > 0)
            HOST.removeChild(HOST.firstChild)
        let IDs = new Set()
        if (L)
            for (let l of L) {
                create_item(l)
                if (l.id) IDs.add(l.id)
            }
        for (let l of items) {
            if (l.id) {
                if (!IDs.has(l.id))
                    create_item(l)
            } else create_item(l)
        }
    }

    function savelist() {
        if (HOST) {
            let L = []
            let I = HOST.querySelectorAll('.todo-item')
            if (I.length > 0) {
                for (let i of I) {
                    let h = i.querySelectorAll('.' + HEADER_TITLE_CSS)
                    let d = i.querySelectorAll('.' + DESC_CSS)
                    let item = { id: i.id, title: '', desc: '' }
                    if (h.length > 0) item.title = h[0].innerHTML
                    if (d.length > 0) item.desc = d[0].innerHTML
                    L.push(item)
                }
            }
            if (L.length < 1 && !confirm('Save empty?')) return
            let sL = JSON.stringify(L)
            localStorage.setItem(LS_KEY, sL)
            tq.ntf('Todo list saved', 'ntf-ok')
        } else tq.debug_ntf('Todo list is not initialized properly')
    }

    function create_item(item = { id: null, title: 'Title', desc: '' }) {
        if (HOST) {
            let itemdiv = document.createElement('div')
            let headerdiv = document.createElement('div')
            let titlediv = document.createElement('div')
            let descdiv = document.createElement('div')
            let collapse = document.createElement('button')


            itemdiv.id = item.id ? item.id : new Date().getTime()
            itemdiv.classList.add(TODO_ITEM)
            headerdiv.appendChild(titlediv)
            headerdiv.appendChild(collapse)
            headerdiv.classList.add(HEADER_CSS)
            descdiv.classList.add('hidden', DESC_CSS)
            titlediv.classList.add(HEADER_TITLE_CSS);
            titlediv.setAttribute(CE, 'true')
            descdiv.setAttribute(CE, 'true')
            itemdiv.appendChild(headerdiv)
            itemdiv.appendChild(descdiv)
            itemdiv.onclick = function() { itemdiv.classList.toggle(SELECTED_CSS) }
            collapse.classList.add('todo-collapse', 'todo-collapse-down')
            collapse.onclick = function() {
                descdiv.classList.toggle('hidden')
                if (descdiv.classList.contains('hidden')) {
                    collapse.classList.add('todo-collapse-down')
                    collapse.classList.remove('todo-collapse-up')
                } else {
                    collapse.classList.remove('todo-collapse-down')
                    collapse.classList.add('todo-collapse-up')
                }
            }

            titlediv.innerHTML = item.title
            descdiv.innerHTML = item.desc

            HOST.appendChild(itemdiv)
        } else tq.debug_ntf('Todo list is not initialized properly')
    }

    function toggle() {
        document.getElementById(HOST_WRAPPER_ID).classList.toggle('hidden')
    }

    function remove_selected() {
        if (HOST) {
            if (confirm("Confirm deleting all selected todo items.")) {
                let selected = HOST.querySelectorAll('.' + SELECTED_CSS)
                if (selected.length > 0)
                    for (let s of selected)
                        s.remove()
            }
        }
    }

    function clear() {
        if (HOST) {
            if (HOST.children.length > 0 && !confirm('Clear the list?')) return
            while (HOST.children.length > 0)
                HOST.removeChild(HOST.firstChild)
        }
    }

    function parse_selected() {
        let selected = HOST.querySelectorAll('.' + SELECTED_CSS)
        if (selected.length > 0)
            for (let s of selected) {
                let h = s.querySelectorAll('.' + HEADER_TITLE_CSS)
                let d = s.querySelectorAll('.' + DESC_CSS)
                if (h.length > 0) h[0].innerHTML = h[0].innerText
                if (d.length > 0) d[0].innerHTML = d[0].innerText
            }

    }

    return {
        LS_KEY,
        toggle,
        loadlist,
        savelist,
        create_item,
        remove_selected,
        parse_selected,
        clear,
        merge
    }
}

function export_range() {
    const d = tq.getDatesFromInputs()
    if (d) {
        const f = moment(d[0]).format('YYMMDD-HHmm');
        const t = moment(d[1]).format('YYMMDD-HHmm');
        export_data(d[0], d[1], `tfq-${f}::${t}.data`)
    }
}

function export_data(fromdate, todate, filename) {
    if (tq && todos) {
        // let frames = localStorage.getItem(tq.LS_KEY)
        let todolist = localStorage.getItem(todo.LS_KEY)
        let frames = []
        if (fromdate && todate) {
            if (!isNaN(fromdate.getTime()) && !isNaN(fromdate.getTime())) {
                for (let i of tq.items.get())
                    if (i.start > fromdate && i.end < todate)
                        frames.push(i)
            } else tq.ntf('Export dates are invalid', 'ntf-fail', 4000)
        } else frames = tq.items.get()
        let exp = {
            frames: frames,
            todo: todolist ? JSON.parse(todolist) : null
        }
        let asjson = JSON.stringify(exp)
        if (!filename) filename = `tfq-${moment().format('YYMMDD-HHmm')}.data`
        save_to_file(asjson, filename)
    }
}

function import_data() {
    load_file_sync().then((d) => {
        if (d && tq && todo) {
            let data = JSON.parse(d)
            try {
                if (data.frames) {
                    tq.merge(data.frames)
                }
                if (data.todo) {
                    todo.merge(data.todo)
                }
                tq.ntf('Lists merged', 'ntf-ok')
            } catch (ex) {
                tq.ntf('There was an error in the import, see the console')
                console.log(ex)
            }
        }
    }).catch((x) => {
        if (tq) tq.ntf('Import failed, see the reason in the console', 'ntf-fail')
        console.log(x)
    })
}

function save_to_file(text, filename, type = 'text/plain') {
    let a = document.createElement("a")
    let file = new Blob([text], { type: type })
    a.href = URL.createObjectURL(file)
    a.download = filename
    a.click()
}

function load_file_sync() {
    return new Promise(
        function(resolve, reject) {
            let upl = document.createElement("input")
            let state = 0
            upl.setAttribute('type', 'file')
            upl.onchange = function() {
                if (upl.files.length > 0) {
                    var fr = new FileReader()
                    fr.onload = function(e) {
                        state = 1;
                        resolve(e.target.result)
                    }
                    fr.onerror = function(e) {
                        state = 1;
                        reject(e)
                    }
                    fr.readAsText(upl.files.item(0))
                } else reject(e)
            }
            setTimeout(() => {
                // in case you cancel the file open dialog
                // it doesn't fire a browser notification
                if (state < 1)
                    reject('timeout')
            }, 30000)
            upl.click()
        })
}