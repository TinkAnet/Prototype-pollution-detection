const path = require("path");

// Hack: Stop this plugin clobbering any other uses of Prism
// Related bug: https://github.com/PrismJS/prism/issues/3636
const globalPrism = global.Prism;
const Prism = require("prismjs");
global.Prism = globalPrism;
// Endhack

const prettier = require("prettier");
const fs = require("fs");

const defaults = {
  path: path.join(".", "demos"),
  parsers: {
    html: "html",
    css: "css",
    javascript: "babel",
  },
  displayNames: {
    html: "HTML",
    css: "CSS",
    javascript: "JavaScript",
    result: "Result",
  },
  filenames: {
    html: "index.*",
    css: "styles.css",
    javascript: "main.js",
  },
  open: {
    html: false,
    css: false,
    javascript: false,
    result: true,
  },
  prettier: true,
};

function deepMerge(base, overrides) {
  const returnObj = {};
  Object.keys(base).forEach((key) => {
    if (typeof base[key] === "object" && overrides[key] !== undefined) {
      return (returnObj[key] = deepMerge(base[key], overrides[key]));
    } else if (overrides[key] !== undefined) {
      return (returnObj[key] = overrides[key]);
    }

    returnObj[key] = base[key];
  });

  return returnObj;
}

function stripTrailingSlashes(str) {
  let end = str.length;
  while (str[--end] === "/");
  return str.slice(0, end + 1);
}

function demoFileExists(path) {
  try {
    fs.accessSync(path);
    return true;
  } catch (e) {
    return false;
  }
}

module.exports = function demo(eleventyConfig, userOptions = {}) {
  const options = deepMerge(defaults, userOptions);
  options.path = stripTrailingSlashes(options.path);
  const demos = [];

  eleventyConfig.addWatchTarget(`${options.path}/**/*`);

  eleventyConfig.addCollection("demos", (collectionApi) => {
    const filtered = collectionApi.getFilteredByGlob(
      `${options.path}/**/${options.filenames.html}`
    );

    demos.push(...filtered);

    return filtered;
  });

  [
    { name: "demoCss", language: "css", tag: "style" },
    { name: "demoJS", language: "javascript", tag: "script" },
  ].forEach(({ name, language, tag }) => {
    eleventyConfig.addShortcode(name, function () {
      const pagePath = path.dirname(path.resolve(this.page.inputPath));
      const page = demos.find(
        (page) => path.dirname(path.resolve(page.inputPath)) === pagePath
      );
      const filename =
        page.data?.filenames?.[language] || options.filenames[language];
      const filepath = path.join(pagePath, filename);
      if (demoFileExists(filepath)) {
        try {
          return `<${tag}>${fs.readFileSync(filepath, "utf-8")}</${tag}>`;
        } catch (e) {
          throw new Error(
            `Problem trying to load demo file "${filepath}": ${e}`
          );
        }
      }
      return "";
    });
  });

  eleventyConfig.addShortcode("embeddedDemo", function (demoName) {
    if (!demoName) {
      throw new Error("No demo name passed");
    }

    const searchPath = stripTrailingSlashes(
      path.join(path.resolve("."), options.path, demoName)
    );

    const page = demos.find(
      (page) => path.dirname(path.resolve(page.inputPath)) === searchPath
    );

    const files = [];
    files.push({ code: page.templateContent, language: "html" });

    ["css", "javascript"].forEach((language) => {
      const filename =
        page.data?.filenames?.[language] || options.filenames[language];
      const filepath = path.join(searchPath, filename);
      if (demoFileExists(filepath)) {
        try {
          files.push({ code: fs.readFileSync(filepath, "utf-8"), language });
        } catch (e) {
          throw new Error(
            `Problem trying to load demo file "${filepath}": ${e}`
          );
        }
      }
    });

    const blocks = files.map(({ code, language }) => {
      const highlighted = Prism.highlight(
        options.prettier
          ? prettier.format(code, { parser: options.parsers[language] })
          : code,
        Prism.languages[language],
        language
      );

      const lines = highlighted.split("\n").slice(0, -1);

      return `<details class="eleventy-plugin-embedded-demo__code" ${
        options.open[language] && "open"
      }>
  <summary class="eleventy-plugin-embedded-demo__code-toggle">${
    options.displayNames[language]
  }</summary>
  <pre class="language-${language}"><code class="language-${language}">${lines.join(
        "<br>"
      )}</code></pre>
</details>`;
    });

    return `<div class="eleventy-plugin-embedded-demo__container">
  ${blocks.join("")}
  <details class="eleventy-plugin-embedded-demo__result" ${
    options.open.result && "open"
  }>
    <summary class="eleventy-plugin-embedded-demo__result-toggle">${
      options.displayNames.result
    }</summary>
    <iframe src="${
      page.url
    }" title="${page.data.title}" loading="lazy" class="eleventy-plugin-embedded-demo__result-iframe"></iframe>
  </details>
</div>`;
  });
};

module.exports.defaults = defaults;
