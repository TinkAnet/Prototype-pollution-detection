/**
 * Set to nested object by keys.
 * # Examples
 *
 * ## 1. Simple set to nested object
 * ```javascript
 * const keys = ['a', 'b', 'c', 'd', 'e', 'f'];
 * const nestedObject = {
 *   a: {
 *     b: {
 *       c: {
 *         d: {
 *           e: {
 *             f: {},
 *           },
 *         },
 *       },
 *     },
 *   },
 * };
 * setValueToObject(nestedObject, keys, 'Depth 6 Test');
 * console.assert(nestedObject.a.b.c.d.e.f === 'Depth 6 Test');
 * ```
 *
 * ## 2. If the number of keys > object
 * - Create a new object and assign value to it.
 * ```javascript
 *   const keys = ['dog', 'tater.man', 'hi'];
 *   const nestedObject = {
 *     dog: {
 *       'tater.man': {},
 *     },
 *   };
 *   setValueToObject(nestedObject, keys, 'Depth 3 Test');
 *   console.assert(nestedObject.dog['tater.man']['hi'] === 'Depth 3 Test');
 * ```
 */
export function setValueToObject<T>(obj, keys: string[], value: T) {
  let refObj = obj; // Each loop points to a nested object.
  for (let index = 0; index < keys.length - 1; index++) {
    refObj = refObj[keys[index]]; // Go into nest object...(except last nest key)
  }
  const lastKey = keys[keys.length - 1];
  refObj[lastKey] = value;
}

/**
 * Create nested object from keys
 * @export
 * @template T
 * @param {Array<T>} array
 * @return {*}  {Record<string, any>}
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function arrayToNestObj<T extends string | number | symbol>(array: Array<T>): Record<string, any> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let nestedObject: any = {};
  for (let i = array.length - 1; i >= 0; i--) {
    const key = array[i];
    nestedObject = { [key]: nestedObject };
  }
  return nestedObject;
}

/**
 *
 *
 * @export
 * @param {object} target
 * @param {object} source
 * @return new merged object
 * # Examples
 * ```javascript
 * const obj1 = { a: 1, b: { c: 2 } };
 * const obj2 = { b: { d: 3 }, e: 4 };
 * const mergedObj = deepMerge(obj1, obj2);
 * console.assert(JSON.stringify(mergedObj) === JSON.stringify({ a: 1, b: { c: 2, d: 3 }, e: 4 }));
 * ```
 */
export function deepMerge(target: object, source: object): object {
  if (isObject(target) && isObject(source)) {
    const merged = { ...target };

    for (const key in source) {
      if (isObject(source[key])) {
        if (!(key in target)) {
          Object.assign(merged, { [key]: source[key] });
        } else {
          merged[key] = deepMerge(target[key], source[key]);
        }
      } else {
        Object.assign(merged, { [key]: source[key] });
      }
    }

    return merged;
  }

  return source;
}

function isObject(item: unknown): boolean {
  return item !== null && typeof item === 'object' && !Array.isArray(item);
}
