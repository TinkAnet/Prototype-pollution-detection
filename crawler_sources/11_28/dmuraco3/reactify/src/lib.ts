type RuleMap = {[key:string]: {[key:string]:string}};

const getStyleMap = (stylesheets: CSSStyleSheet[]): RuleMap  => {
    let cssRulesMap: RuleMap = {};

    for (let ii=0;ii<stylesheets.length;ii++) {
        try {
            const stylesheet = stylesheets[ii];
            const rules = stylesheet.cssRules;
            Array.from(rules).forEach((rule) => {
                if (rule && rule instanceof CSSStyleRule) {

                    if (!cssRulesMap[rule.selectorText]) {
                        cssRulesMap[rule.selectorText] = {};
                    }
                    const style = rule.style;
                    Array.from(style).forEach((property) => {
                        cssRulesMap[rule.selectorText][property] = style.getPropertyValue(property);
                    });
                };
            })
        } catch (e) {}
    }
    return cssRulesMap;
}

function hyphenToCamel(hyphen: string): string { return hyphen.replace(/-([a-z])/g, g => g[1].toUpperCase()); }


function craftCSSRule(property: string, value: string) {
    // conditionally pad with quotes
    value = value.replaceAll('"', "'");
    if (!value.startsWith('"')) value = `"${value}`;
    if (!value.endsWith('"')) value = `${value}"`;

    return `${hyphenToCamel(property)}: ${value},`
}

function domNodeToJSX(node: HTMLElement, nestingLevel: number) {
    if (node.nodeType === Node.TEXT_NODE) { return padTab(`{\`${ node.textContent ?? '' }\`}`, nestingLevel) };
    if (node.nodeType !== Node.ELEMENT_NODE) { return '' };

    const tagName = node.tagName.toLowerCase();
    const children: string = Array.from(node.childNodes).map(child => domNodeToJSX(child as HTMLElement, nestingLevel+1)+'\n').join('');

    const parsedStyle = JSON.parse(node.getAttribute("style-list") ?? "[]") as string[];

    const uniqueStyle: Array<string> = Array.from([... new Set(parsedStyle)]);

    const style = uniqueStyle.length>0 ? 
        `style={{\n${uniqueStyle.map(x=>'\t'.repeat(nestingLevel+1)+x+'\n').join('')}${'\t'.repeat(nestingLevel)}}}` 
            : '';

            function padTab(str: string, level: number): string {
                return '\t'.repeat(level) + str;
            }

            const formattedOpenTag = padTab(`<${tagName} ${style}>` + '\n', nestingLevel);
            const formattedChildren = `${children}`;
            const formattedClosetag = padTab(`</${tagName}>`, nestingLevel);

            const ret = formattedOpenTag + formattedChildren + formattedClosetag;
            node.removeAttribute("style-list");
            return ret;
}

function* convertCSSRules(elementRoot: HTMLElement, rules: { [key: string]: string }) {
    for (var property in rules) {
        let value = rules[property].trim();

        const useless = ["unset", "normal", "0px", "initial", "none", "auto"];
        const unset = useless.includes(value);
        if(unset) continue;

        value = value.replace(/var\(\s*(--[\w-]+)\s*\)/, (match, p1, offset, string) => {
            return getComputedStyle(elementRoot).getPropertyValue(p1);
        })

        yield craftCSSRule(property, value);
    };
};

const descendAndStyle = (root: HTMLElement, cssRules: { [key: string]: { [key: string]: string } }) => {
    for (var key in cssRules) {
        let elements = document.querySelectorAll(key);
        elements.forEach((element) => {
            if (!root.contains(element)) return;
            let styles: Array<string> = Array.from(JSON.parse(element.getAttribute("style-list") ?? "[]"));
            let cssRuleIter = convertCSSRules(root,cssRules[key]);
            for (const rule of cssRuleIter) {
                const property = rule.split(':')[0].trim();
                styles.forEach((x,idx)=> {if(x.includes(property)) styles[idx] = rule;})
                if (!styles.includes(rule)) {
                    styles.push(rule);
                };
            };

            const styleTextFromElement = (element as HTMLElement).style.cssText;
            if (styleTextFromElement !== "") {
                styleTextFromElement.split(";").forEach(rule => {
                    if (rule==="")return;
                    let [property,value] = rule.split(":").map(x=>x.trim());
                    const reactRule = craftCSSRule(property, value);
                    if (!styles.includes(rule)) {
                        styles.push(reactRule);
                    }
                })
            }

            element.setAttribute("style-list", JSON.stringify(styles));
        });
    }
}


async function getActiveTab() {
    let [tab] = await chrome.tabs.query({ "active": true, "currentWindow": true });
    return tab.id as number;
}

function getReactFromElement(element: HTMLElement): string {
    
    while (document.readyState !== "complete") { }

    const stylesheets = Array.from(document.styleSheets);

    const styleMap = getStyleMap(stylesheets);
    descendAndStyle(element, styleMap);
    const reactCode = domNodeToJSX(element, 0);
    return reactCode;
}

export type {RuleMap};
export {getStyleMap, hyphenToCamel, domNodeToJSX, descendAndStyle, getActiveTab, getReactFromElement};
