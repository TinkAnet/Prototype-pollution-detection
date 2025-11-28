export default function entryFactory(path, scriptId) {
  return `
    import {render} from '@mybricks/rxui'
    import Page from "${path.replace(/\(.+\)/, '')}";
    
    const parent = document.createElement('div')
    parent.style.height = '100%'
    document.body.appendChild(parent)

    const script = document.querySelector('#${scriptId}')

    render(<Page {...JSON.parse(script.dataset.obj)}/>, parent, () => {
        //parent.replaceWith(...[...parent.childNodes])
        script.replaceWith(...[...script.childNodes])
    })
    
        `
}
