import { parseStringPromise } from "xml2js";
import { stringifyRequest } from "loader-utils";
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { loader } from "webpack";
import { Options } from "./options";

const tagNameKey = "#name";
const innerTextKey = "$innertext";
const textOnlyNodeName = "__text__";
const childrenKey = "$children";
const attributesKey = "$props";

type XmlNode = {
    [tagNameKey]: string;
    [attributesKey]?: Record<string, string>;
    [childrenKey]?: XmlNode[];
    [innerTextKey]?: string;
};

type Result = {
    [key: string]: XmlNode;
};

const stringify = (str: string) =>
    str.replace(/\\/g, "\\\\").replace(/\r/g, "").replace(/\n/g, "\\n");

/**
 * Transforms an XML node into a react-style JS syntax string.
 *
 * @param node - The node to transform.
 * @param tabs - How many tabs to indent.
 * @param isRoot - If this is the root node to spread props to.
 * @returns A string that is valid JavaScript transformed.
 */
function reactify(node: XmlNode, tabs: number, isRoot: boolean): string {
    const indent = "    ".repeat(tabs);
    const tag = node[tagNameKey];

    if (tag === textOnlyNodeName) {
        /* istanbul ignore next */ // the || "" is to appease TS
        return `${indent}"${stringify(node[innerTextKey] || "")}"`;
    }

    let attributes = isRoot ? "props" : "null";
    const rawAttributes = node[attributesKey];
    if (rawAttributes) {
        attributes = `{ ${[...Object.entries(rawAttributes)]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, value]) => `"${key}": "${stringify(value)}"`)
            .join(", ")} }`;

        if (isRoot) {
            attributes = `_extends(${attributes}, props)`;
        }
    }
    let children: string[] | undefined;
    const rawChildren = node[childrenKey];
    if (Array.isArray(rawChildren)) {
        children = rawChildren.map((child) =>
            reactify(child, tabs + 1, false),
        );
    }

    const start = `${indent}/*#__PURE__*/_react.default.createElement(getComponent("${tag}"), ${attributes}`;
    const middle = children
        ? `,\n${children.map((child) => child + ",\n").join("")}${indent}`
        : "";
    const end = ")";

    return start + middle + end;
}

/**
 * The good code.
 *
 * @param loader - The context webpack calls this with.
 * @param xml - The xml contents to transform.
 * @param options - The parsed options to this loader.
 * @returns A promise that resolves to the transformed string.
 */
export async function transform(
    loader: loader.LoaderContext,
    xml: string,
    options: Options,
): Promise<string> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const result: Result = await parseStringPromise(xml, {
        attrkey: attributesKey,
        explicitArray: true,
        explicitChildren: true,
        explicitRoot: true,
        childkey: childrenKey,
        charkey: innerTextKey,
        charsAsChildren: true,
        preserveChildrenOrder: true,
        // explicitRoot: true,
        // */
    });

    const rootKeys = [...Object.keys(result)];
    // XML should only ever have 1 root node.
    // If a way to trigger this can be found add to tests
    /* istanbul ignore next */
    if (rootKeys.length !== 1) {
        throw new Error(
            `Invalid number of root keys in xml: ${rootKeys.join(", ")}`,
        );
    }

    const root = result[rootKeys[0]];

    const reactPath = stringifyRequest(
        loader,
        options.reactPath || require.resolve("react"),
    );

    return `"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = void 0;

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
function _objectWithoutProperties(source, excluded) { if (source == null) return {}; var target = _objectWithoutPropertiesLoose(source, excluded); var key, i; if (Object.getOwnPropertySymbols) { var sourceSymbolKeys = Object.getOwnPropertySymbols(source); for (i = 0; i < sourceSymbolKeys.length; i++) { key = sourceSymbolKeys[i]; if (excluded.indexOf(key) >= 0) continue; if (!Object.prototype.propertyIsEnumerable.call(source, key)) continue; target[key] = source[key]; } } return target; }
function _objectWithoutPropertiesLoose(source, excluded) { if (source == null) return {}; var target = {}; var sourceKeys = Object.keys(source); var key, i; for (i = 0; i < sourceKeys.length; i++) { key = sourceKeys[i]; if (excluded.indexOf(key) >= 0) continue; target[key] = source[key]; } return target; }

var _react = _interopRequireDefault(require(${reactPath}));
function _getComponentDefault(str) {
    return str;
}

${
    root[attributesKey] // if there are attributes, we need to spread them with the props
        ? "function _extends() { _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; }; return _extends.apply(this, arguments); }"
        : ""
}

var XmlAsReactComponent = function XmlAsReactComponent(_ref) {
    var getComponent = _ref.getComponent || _getComponentDefault,
        props = _objectWithoutProperties(_ref, ["getComponent"]);
    return (
${reactify(root, 2, true)}
    );
}

var rootAttributes = ${JSON.stringify(root[attributesKey] || {})};
exports.rootAttributes = rootAttributes;

var _default = XmlAsReactComponent;
exports.default = _default;
exports.Component = XmlAsReactComponent;
`;
}
