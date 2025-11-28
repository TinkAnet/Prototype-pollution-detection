/**
 * Format a date to the format: Month Day Year.
 *
 * @param {Date} date - The date to be formatted.
 * @returns {string} The date in format: Month Day Year.
 * @example
 *  fDate(new Date()) // January 1 9999
 */
export function fDate(date: Date): string {
    const months = [
        "January", "February", "March", "April",
        "May", "June", "July", "August",
        "September", "October", "November", "December"
    ];

    const day = date.getDate();
    const monthIndex = date.getMonth();
    const year = date.getFullYear();

    return `${months[monthIndex]} ${day} ${year}`;
}

/**
 * Format a time to the format: Hours:Minutes[:Seconds].
 *
 * @param {Date} date - The date to be formatted.
 * @param {boolean} [seconds=false] - If true, the seconds will be included in the time.
 * @returns {string} The time in format: Hours:Minutes[:Seconds].
 * @example
 * fTime(new Date()) // 12:00
 * fTime(new Date(), true) // 12:00:00
 */
export function fTime(date: Date, seconds: boolean = false): string {
    const hours = date.getHours();
    const minutes = date.getMinutes();
    const secs = date.getSeconds();

    return `${hours}:${minutes}${seconds ? `:${secs}` : ''}`;
}

/**
 * Calculate the time difference between a given date and today and return a user-friendly string.
 *
 * @param {Date} date - The date to compare with today.
 * @returns {string} A string representing the time difference, e.g., "Today", "Yesterday", or "{X} days ago".
 */
export function dateAmount(date: Date): string {
    const oneDayMs = 24 * 60 * 60 * 1000;
    const today = new Date();
    const diffDays = Math.round(Math.abs((today.getTime() - date.getTime()) / oneDayMs));
    if (diffDays === 0) {
        return "Today";
    } else if (diffDays === 1) {
        return "Yesterday";
    } else {
        return `${diffDays} days ago`;
    }
}

/**
 * Format a number to include comma separators for thousands.
 *
 * @param {number} number - The number to be formatted.
 * @returns {string} The formatted number with comma separators for thousands.
 */
export function fNumber(number: number): string {
    return number.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Convert a JavaScript object (JSON) to XML format.
 *
 * @param {object} json - The JavaScript object (JSON) to be converted to XML.
 * @param {string} [parent_class='root'] - The XML root element name.
 * @returns {string} The XML representation of the given JSON.
 */
export function JsonToXml(json: any, parent_class: string = 'root') {
    const start = '<?xml version="1.0" encoding="UTF-8"?>\n';
    const convert = (json: any, parent = '') => {
        let xml = '';
        for (const key in json) {
            if (json.hasOwnProperty(key)) {
                const element = json[key];
                const tag = parent ? parent + '.' + key : key;
                if (typeof element === 'object') {
                    xml += convert(element, tag);
                } else {
                    xml += `<${tag}>${element}</${tag}>\n`;
                }
            }
        }
        return xml;
    };
    return start + `<${parent_class}>\n` + convert(json) + `</${parent_class}>`;
};

/**
 * Generate a random alphanumeric string of a given length.
 *
 * @param {number} length - The length of the random string to be generated.
 * @returns {string} A random alphanumeric string of the specified length.
 */
export function generateRandomString(length: number): string {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let result = '';
    for (let i = length; i > 0; --i) {
        result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
}


/**
 * Convert a string to a kebab-case format (lowercase words separated by dashes).
 *
 * @param {string} input - The string to be converted to kebab-case.
 * @returns {string} The kebab-case formatted string.
 */
export function toKebabCase(input: string): string {
    return input.toLowerCase().replace(/ /g, '-');
}


/**
 * Deep clone a JavaScript object.
 *
 * @param {object} obj - The object to be cloned.
 * @returns {object} A deep clone of the input object.
 */
export function deepClone(obj: object): object {
    return JSON.parse(JSON.stringify(obj));
}


/**
 * Convert bytes to a human-readable file size with units (e.g., KB, MB, GB).
 *
 * @param {number} bytes - The size in bytes to be converted.
 * @returns {string} The human-readable file size string.
 */
export function bytesToSize(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) {
        return '0 Byte';
    }
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${Math.round(bytes / Math.pow(1024, i))} ${sizes[i]}`;
}


/**
 * Shuffle the elements of an array randomly using the Fisher-Yates (Knuth) algorithm.
 *
 * @param {Array} array - The array to be shuffled.
 * @returns {Array} The shuffled array.
 */
export function shuffleArray(array: any[]): any[] {
    const result = [...array];
    for (let i = result.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
}


/**
 * Check if a value is a valid email address.
 *
 * @param {string} email - The email address to be validated.
 * @returns {boolean} Returns true if the email is valid, otherwise false.
 */
export function isValidEmail(email: string): boolean {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

/**
 * Check if a password is strong enough.
 *
 * @param {string} password - The password to be validated.
 * @param {number} minLength - The minimum length of the password.
 * @returns {object} Returns an object with the following properties:
 * - valid: boolean - true if the password is valid, otherwise false.
 * - message: string - the validation message.
 * - suggestions: string[] - an array of suggestions to improve the password.
 */
export function isStrongPassword(password: string, minLength: number = 8): { valid: boolean, message: string, suggestions: string[] } {
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecialChar = /[^A-Za-z0-9]/.test(password); // Non-alphanumeric characters

    const criteria = [
        { condition: hasUppercase, message: "Include at least one uppercase letter (A-Z)." },
        { condition: hasLowercase, message: "Include at least one lowercase letter (a-z)." },
        { condition: hasDigit, message: "Include at least one digit (0-9)." },
        { condition: hasSpecialChar, message: "Include at least one special character (e.g., !@#$%)." }
    ];

    const suggestions = criteria.filter(criterion => !criterion.condition).map(criterion => criterion.message);

    if (password.length < minLength) {
        return {
            valid: false,
            message: `Password must be at least ${minLength} characters long.`,
            suggestions
        };
    }

    if (suggestions.length > 0) {
        return {
            valid: false,
            message: "Password must meet the following criteria:",
            suggestions
        };
    }

    return {
        valid: true,
        message: "Password is strong.",
        suggestions: []
    };
}


/**
 * Remove any duplicate elements from an array.
 * @param {Array} array - The array to be deduplicated.
 * @returns {Array} The deduplicated array.
 */
export function removeDuplicates(array: any[]): any[] {
    const t = [...array];

    return t.filter((item, index) => t.indexOf(item) === index);
}

/**
 * Convert an object to a query string.
 * @param {object} obj - The object to be converted.
 * @returns {string} The query string.
 * @example
 * objectToQueryString({ foo: 'bar', baz: 42 }); // Returns: "?foo=bar&baz=42"
 */

export function objectToQueryString(obj: object, urlSafe?: boolean): string {
    return '?' + Object.keys(obj).map(key => `${key}=${urlSafe ? encodeURIComponent(obj[key]) : obj[key]}`).join('&');
}

/**
 * Truncate a string to a given length.
 * @param {string} str - The string to be truncated.
 * @param {number} maxLength - The maximum length of the string.
 * @returns {string} The truncated string.
 * @example
 * truncateString('Lorem ipsum dolor sit amet', 10); // Returns: "Lorem ipsu..."
 */
export function truncateString(str: string, maxLength: number): string {
    if (str.length > maxLength) {
        return str.substring(0, maxLength - 3) + '...';
    }
    return str;
}



/**
 * Divide an array into chunks of a given size.
 * @param {Array} array - The array to be chunked.
 * @param {number} chunkSize - The size of each chunk.
 * @returns {Array} The chunked array.
 * @example
 * chunkArray([1, 2, 3, 4, 5, 6, 7], 3); // Returns: [[1, 2, 3], [4, 5, 6], [7]]
 */
export function chunkArray(array: any[], chunkSize: number): any[] {
    const result = [];
    for (let i = 0; i < array.length; i += chunkSize) {
        result.push(array.slice(i, i + chunkSize));
    }
    return result;
}

/**
 * Sort an array of objects by a given property.
 * @param {Array} array - The array to be sorted.
 * @param {string} property - The property to sort by.
 * @returns {Array} The sorted array.
 * @example
 * const users = [
 *    { name: 'John', age: 25 },    
 *   { name: 'Jane', age: 22 },
 *   { name: 'Jack', age: 27 }
 * ];
 * 
 * sortByProperty(users, 'age'); // Returns: [{ name: 'Jane', age: 22 }, { name: 'John', age: 25 }, { name: 'Jack', age: 27 }]
 */
export function sortByProperty(array: any[], property: string): any[] {
    return array.sort((a, b) => {
        if (a[property] < b[property]) {
            return -1;
        }
        if (a[property] > b[property]) {
            return 1;
        }
        return 0;
    });
}

/**
 * Validate a URL.
 * @param {string} url - The URL to be validated.
 * @returns {boolean} Returns true if the URL is valid, otherwise false.
 * @example
 * isValidURL("https://www.example.com"); // Returns: true
 * isValidURL("example.com"); // Returns: false
 */

export function isVaildUrl(url: string): boolean {
    const regex = /^(ftp|http|https):\/\/[^ "]+$/;
    return regex.test(url);
}

/**
 * Find the common elements between two arrays.
 * @param {Array} array1 - The first array.
 * @param {Array} array2 - The second array.
 * @returns {Array} The common elements between the two arrays.
 * @example
 * arrayIntersection([1, 2, 3], [2, 3, 4]); // Returns: [2, 3]
 */

export function arrayIntersection(array1: any[], array2: any[]): any[] {
    return array1.filter(x => array2.includes(x));
}


/**
 * Deep merge two objects.
 * @param {object} target - The target object.
 * @param {object} source - The source object.
 * @returns {object} The merged object.
 * @example
 * deepMerge({ a: { b: 1 } }, { a: { c: 2 } }); // Returns: { a: { b: 1, c: 2 } }
 */
export function deepMerge(target: object, source: object): object {
    const isObject = (obj: object) => obj && typeof obj === 'object';

    if (!isObject(target) || !isObject(source)) {
        return source;
    }

    Object.keys(source).forEach(key => {
        const targetValue = target[key];
        const sourceValue = source[key];

        if (Array.isArray(targetValue) && Array.isArray(sourceValue)) {
            target[key] = targetValue.concat(sourceValue);
        } else if (isObject(targetValue) && isObject(sourceValue)) {
            target[key] = deepMerge(Object.assign({}, targetValue), sourceValue);
        } else {
            target[key] = sourceValue;
        }
    });

    return target;
}


/**
 *  Check if a string is a palindrome.
 * @param {string} str
 * @returns {boolean} Returns true if the string is a palindrome, otherwise false.
 * @example
 * palindromeChecker('racecar'); // Returns: true
 * palindromeChecker('hello'); // Returns: false
 */
export function palindromeChecker(str: string): boolean {
    const reversedStr = str.toLowerCase().split('').reverse().join('');
    return str === reversedStr;
}

// String Capitalization

/**
 * Capitalize the first letter of a string.
 * @param {string} str - The string to be capitalized.
 * @returns {string} The capitalized string.
 * @example
 * capitalize('hello world'); // Returns: "Hello world"
 */
export function capitalize(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Convert a string to camel case.
 * @param {string} str - The string to be converted.
 * @returns {string} The camel cased string.
 * @example
 * toCamelCase('Hello world'); // Returns: "helloWorld"
 */
export function toCamelCase(str: string): string {
    return str.replace(/(?:^\w|[A-Z]|\b\w)/g, (word, index) => {
        return index === 0 ? word.toLowerCase() : word.toUpperCase();
    }).replace(/\s+/g, '');
}


/**
 * Parses query string parameters into an object.
 * @param {string} queryString - The query string to be parsed.
 * @returns {object} The parsed query string parameters.
 * @example
 * parseQueryString('?page=1&size=10'); // Returns: { page: '1', size: '10' }
 */

export function parseQueryString(queryString: string): object {
    const params = new URLSearchParams(queryString);
    return Array.from(params.keys()).reduce((acc, key) => {
        acc[key] = params.get(key);
        return acc;
    }, {});
}

/**
 * Flatten an array.
 * @param {Array} array - The array to be flattened.
 * @returns {Array} The flattened array.
 * @example
 * flattenArray([1, [2], 3, 4]); // Returns: [1, 2, 3, 4]
 */
export function flattenArray(array: any[]): any[] {
    return array.reduce((acc, val) => acc.concat(val), []);
}

/**
 * Calculate the average of an array of numbers.
 * @param {Array} array - The array of numbers.
 * @returns {number} The average of the numbers.
 * @example
 * arrayAverage([1, 2, 3, 4]); // Returns: 2.5
 */
export function arrayAverage(array: number[]): number {
    return array.reduce((acc, val) => acc + val, 0) / array.length;
}

/**
 * Calculate the sum of an array of numbers.
 * @param {Array} array - The array of numbers.
 * @returns {number} The sum of the numbers.
 * @example
 * arraySum([1, 2, 3, 4]); // Returns: 10
 */
export function arraySum(array: number[]): number {
    return array.reduce((acc, val) => acc + val, 0);
}

/**
 * Calculate the Levenshtein distance between two strings.
 * @param {string} str1 - The first string.
 * @param {string} str2 - The second string.
 * @returns {number} The Levenshtein distance between the two strings.
 * @example
 * levenshteinDistance("kitten", "sitting"); // Returns: 3
 */

export function levenshteinDistance(str1: string, str2: string): number {
    const track = Array(str2.length + 1).fill(null).map(() =>
        Array(str1.length + 1).fill(null));
    for (let i = 0; i <= str1.length; i += 1) {
        track[0][i] = i;
    }
    for (let j = 0; j <= str2.length; j += 1) {
        track[j][0] = j;
    }
    for (let j = 1; j <= str2.length; j += 1) {
        for (let i = 1; i <= str1.length; i += 1) {
            const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
            track[j][i] = Math.min(
                track[j][i - 1] + 1,
                track[j - 1][i] + 1,
                track[j - 1][i - 1] + indicator,
            );
        }
    }
    return track[str2.length][str1.length];
}

/**
 * Validate an object against a schema.
 * @param {object} obj - The object to be validated.
 * @param {object} schema - The schema object.
 * @returns {object} The validation result.
 * @example
 * validateAgainstSchema({ name: 'John', age: 30 }, { name: 'string', age: 'number' }); // Returns: { isValid: true, invalidProperties: [] }
*/

export function validateAgainstSchema(obj: object, schema: object): object {
    const objKeys = Object.keys(obj);
    const schemaKeys = Object.keys(schema);

    const invalidProperties = objKeys.reduce((acc, key) => {
        if (schemaKeys.includes(key)) {
            const type = schema[key];
            const value = obj[key];
            if (typeof value !== type) {
                acc.push(key);
            }
        }
        return acc;
    }, []);

    return {
        isValid: invalidProperties.length === 0,
        invalidProperties,
    };
}
/**
 * Convert a hex color to RGB.
 * @param {string} hex - The hex color.
 * @returns {string} The RGB color.
 * @example
 * hexToRGB('#ffffff'); // Returns: "rgb(255, 255, 255)"
 */

export function hexToRGB(hex: string): string {
    const hexValue = hex.replace('#', '');
    const r = parseInt(hexValue.substring(0, 2), 16);
    const g = parseInt(hexValue.substring(2, 4), 16);
    const b = parseInt(hexValue.substring(4, 6), 16);
    return `rgb(${r}, ${g}, ${b})`;
}