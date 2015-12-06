
function log () {
  var args = [].slice.call(arguments)
  if(process.title === 'browser') {
    var pre = document.createElement('pre')
    pre.textContent = args.join(' ')
    document.body.appendChild(pre)
  }
  console.log.apply(console, args)
}


if('browser' === process.title) {
  var w = new Worker('./worker.js')
  w.onmessage = function (ev) {
    log(ev.data)
  }
}
