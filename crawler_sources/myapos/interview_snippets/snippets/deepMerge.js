// https://www.greatfrontend.com/questions/javascript/deep-merge

const isString = (val) => typeof val === "string";
const isBoolean = (val) => typeof val === "boolean";
const isNumber = (val) => typeof val === "number";
const isObject = (val) => typeof val === "object" && !Array.isArray(val);
const isEmptyObject = (val) => Object.keys(val).length === 0;
const isPrimitive = (val) =>
  isString(val) ||
  isBoolean(val) ||
  isNumber(val) ||
  val === null ||
  isEmptyObject(val);
const isSameType = (a, b) => typeof a === typeof b && a !== null && b !== null;

/**
 * @param {Object|Array} valA
 * @param {Object|Array} valB
 * @returns Object|Array
 */
export default function deepMerge(valA, valB) {
  if (valA === null || valB === null) {
    return null;
  }

  if (
    isObject(valA) &&
    !isEmptyObject(valA) &&
    isObject(valB) &&
    isEmptyObject(valB)
  ) {
    return valA;
  }

  if (
    isObject(valB) &&
    !isEmptyObject(valB) &&
    isObject(valA) &&
    isEmptyObject(valA)
  ) {
    return valB;
  }

  if (Array.isArray(valA) && Array.isArray(valB)) {
    return [...valA, ...valB];
  }

  let cloned = {};

  if (isObject(valA) && isObject(valB)) {
    cloned = {
      ...valA,
    };
    Object.entries(valB).forEach(([key, value]) => {
      if (cloned[key]) {
        cloned[key] = deepMerge(valA[key], valB[key]);
      } else {
        cloned[key] = value;
      }
    });

    return cloned;
  }
  return valB;
}
