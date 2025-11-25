import type { XoConfigItem } from "xo";

/** Merge XO options. */
declare function merge(base: XoConfigItem, ...patches: XoConfigItem[]): XoConfigItem;

/** Delete typescript-eslint rules. */
export function stripTs(config: XoConfigItem): XoConfigItem;

/** XO options to enable \@babel/eslint-parser. */
declare const babel: XoConfigItem;

/** XO options for JavaScript source. */
declare const js: XoConfigItem;

/** XO options for TypeScript source. */
declare const ts: XoConfigItem;

/** XO options for literate programming. */
declare const literate: XoConfigItem;

/** XO options for webpage. */
declare const web: XoConfigItem;

/** XO options for Preact component. */
declare const preact: XoConfigItem;

/** XO options for RE:DOM component. */
declare const redom: XoConfigItem;

/** XO options for Puppeteer script. */
declare const pptr: XoConfigItem;
