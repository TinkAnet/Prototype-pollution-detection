/**
 * Sanitization utilities using trusted libraries
 * Provides secure parameter sanitization to prevent XSS, injection attacks, and prototype pollution
 */

import DOMPurify from "isomorphic-dompurify"
import validator from "validator"

/**
 * Configuration options for sanitization
 */
export type SanitizationOptions = {
    /** Whether to allow HTML tags in strings */
    allowHtml?: boolean
    /** Custom allowed HTML tags (only used if allowHtml is true) */
    allowedTags?: string[]
    /** Custom allowed HTML attributes (only used if allowHtml is true) */
    allowedAttributes?: string[]
    /** Whether to preserve whitespace */
    preserveWhitespace?: boolean
    /** Maximum string length (strings will be truncated) */
    maxLength?: number
}

/**
 * Default sanitization options
 */
const DEFAULT_OPTIONS: SanitizationOptions = {
    allowHtml: false,
    allowedTags: [],
    allowedAttributes: [],
    preserveWhitespace: false,
    maxLength: 10000, // Prevent DoS attacks with extremely long strings
}

/**
 * Sanitize a string value using DOMPurify and validator.js
 */
export const sanitizeString = (
    value: string,
    options: SanitizationOptions = {
    },
): string => {
    const opts = {
        ...DEFAULT_OPTIONS,
        ...options
    }

    // Truncate if too long (prevent DoS)
    let sanitized
        = value.length > opts.maxLength!
            ? value.substring( 0, opts.maxLength! )
            : value

    if ( opts.allowHtml ) {
        // Allow specific HTML tags and attributes
        sanitized = DOMPurify.sanitize( sanitized, {
            ALLOWED_TAGS: opts.allowedTags,
            ALLOWED_ATTR: opts.allowedAttributes,
            KEEP_CONTENT: true,
        } )
    }
    else {
        // For non-HTML content, only use DOMPurify for actual HTML tags
        // but preserve safe special characters like &, <, >
        const hasActualHtml = /<[a-z][^>]*>/i.test( sanitized )

        if ( hasActualHtml ) {
            // Use DOMPurify to strip HTML and dangerous content
            sanitized = DOMPurify.sanitize( sanitized, {
                ALLOWED_TAGS: [], // No HTML tags allowed
                ALLOWED_ATTR: [], // No attributes allowed
                KEEP_CONTENT: true, // Keep text content
            } )
        }

        // Additional aggressive security measures
        sanitized = sanitized
            .replace( /javascript\s*:/gi, "" ) // Remove javascript: protocol
            .replace( /data\s*:/gi, "" ) // Remove data: protocol (can be dangerous)
            .replace( /vbscript\s*:/gi, "" ) // Remove vbscript: protocol
            .replace( /on\w+\s*=/gi, "" ) // Remove event handlers
            .replace( /expression\s*\(/gi, "" ) // Remove CSS expressions
            .replace( /url\s*\(/gi, "" ) // Remove CSS url() calls
            .replace( /alert\s*\(/gi, "" ) // Remove alert calls
            .replace( /msgbox\s*\(/gi, "" ) // Remove msgbox calls
            .replace( /eval\s*\(/gi, "" ) // Remove eval calls
            .replace( /setTimeout\s*\(/gi, "" ) // Remove setTimeout calls
            .replace( /setInterval\s*\(/gi, "" ) // Remove setInterval calls
    }

    // Handle whitespace
    if ( !opts.preserveWhitespace ) {
        sanitized = sanitized.trim()
    }

    return sanitized
}

/**
 * Check for prototype pollution attempts
 */
export const hasPrototypePollution = ( data: any ): boolean => {
    if ( typeof data !== "object" || data === null )
        return false

    const checkObject = ( obj: any, depth: number = 0 ): boolean => {
        if ( depth > 10 )
            return false // Prevent deep recursion DoS

        try {
            // Check for __proto__ pollution - this can happen in two ways:
            // 1. Direct assignment: obj.__proto__ = { polluted: true }
            // 2. Object literal: { __proto__: { polluted: true } }

            // For object literals, __proto__ doesn't become an own property,
            // but the prototype gets modified. Check if prototype has suspicious properties.
            const proto = Object.getPrototypeOf( obj )
            if (
                proto
                && proto !== Object.prototype
                && proto !== Array.prototype
            ) {
                // Check if the prototype has properties that shouldn't be there
                const protoKeys = Object.getOwnPropertyNames( proto )
                if (
                    protoKeys.some( key => key !== "constructor" && key !== "__proto__" )
                ) {
                    return true
                }
            }

            // Also check for explicit __proto__ property (less common but possible)
            if (
                obj.hasOwnProperty( "__proto__" )
                && typeof obj.__proto__ === "object"
                && obj.__proto__ !== null
            ) {
                return true
            }

            // Check for constructor pollution
            if (
                obj.hasOwnProperty( "constructor" )
                && typeof obj.constructor === "object"
                && obj.constructor !== null
            ) {
                return true
            }

            // Check for prototype pollution
            if (
                obj.hasOwnProperty( "prototype" )
                && typeof obj.prototype === "object"
                && obj.prototype !== null
            ) {
                return true
            }

            // Check nested objects
            for ( const [ key, value ] of Object.entries( obj ) ) {
                if (
                    key !== "__proto__"
                    && key !== "constructor"
                    && key !== "prototype"
                    && typeof value === "object"
                    && value !== null
                    && !Array.isArray( value )
                ) {
                    if ( checkObject( value, depth + 1 ) ) {
                        return true
                    }
                }
            }

            return false
        }
        catch {
            // If we can't safely check, assume it's dangerous
            return true
        }
    }

    return checkObject( data )
}

/**
 * Sanitize parameters recursively to prevent various attacks
 */
export const sanitizeParams = (
    params: any,
    options: SanitizationOptions = {
    },
): any => {
    // Handle null/undefined
    if ( params === null || params === undefined ) {
        return params
    }

    // Handle primitives
    if ( typeof params !== "object" ) {
        if ( typeof params === "string" ) {
            return sanitizeString( params, options )
        }
        return params
    }

    // Handle arrays
    if ( Array.isArray( params ) ) {
        return params.map( item => sanitizeParams( item, options ) )
    }

    // Check for prototype pollution BEFORE processing
    if ( hasPrototypePollution( params ) ) {
        throw new Error( "Prototype pollution attempt detected" )
    }

    // Handle objects - filter out dangerous keys
    const sanitized: any = {
    }

    for ( const [ key, value ] of Object.entries( params ) ) {
        // Skip dangerous keys completely
        if (
            key === "__proto__"
            || key === "constructor"
            || key === "prototype"
        ) {
            continue // Skip these keys
        }

        // Sanitize the key itself
        const sanitizedKey = sanitizeString( key, {
            ...options,
            allowHtml: false, // Keys should never contain HTML
            maxLength: 100, // Reasonable key length limit
        } )

        // Skip if key becomes empty after sanitization
        if ( !sanitizedKey ) {
            continue
        }

        // Recursively sanitize the value
        sanitized[ sanitizedKey ] = sanitizeParams( value, options )
    }

    return sanitized
}

/**
 * Validate and sanitize common data types
 */
export const sanitizers = {
    /**
     * Sanitize email addresses
     */
    email: ( email: string ): string | null => {
        if ( typeof email !== "string" )
            return null

        const sanitized = sanitizeString( email, {
            allowHtml: false
        } )

        // Reject if sanitization removed dangerous content
        if ( sanitized !== email && email.includes( "<" ) ) {
            return null
        }

        const normalized = validator.normalizeEmail( sanitized )

        return normalized && validator.isEmail( normalized ) ? normalized : null
    },

    /**
     * Sanitize URLs
     */
    url: ( url: string ): string | null => {
        if ( typeof url !== "string" )
            return null

        const sanitized = sanitizeString( url, {
            allowHtml: false
        } )

        // Reject if sanitization removed dangerous content
        if ( sanitized !== url && url.includes( "<" ) ) {
            return null
        }

        // Don't validate if sanitization removed too much content
        if ( sanitized.length === 0 )
            return null

        try {
            return validator.isURL( sanitized, {
                protocols: [ "http", "https" ],
                require_protocol: true,
                require_valid_protocol: true,
                allow_underscores: true,
                allow_trailing_dot: false,
                allow_protocol_relative_urls: false,
            } )
                ? sanitized
                : null
        }
        catch {
            return null
        }
    },

    /**
     * Sanitize phone numbers
     */
    phone: ( phone: string ): string | null => {
        if ( typeof phone !== "string" )
            return null

        const sanitized = sanitizeString( phone, {
            allowHtml: false
        } )

        // Don't validate if sanitization removed too much content
        if ( sanitized.length === 0 )
            return null

        try {
            // More permissive phone validation
            if (
                validator.isMobilePhone( sanitized, "any", {
                    strictMode: false
                } )
            ) {
                return sanitized
            }

            // Fallback: basic phone number pattern (more permissive)
            const phonePattern = /^\+?[\d\s\-().]{7,20}$/
            return phonePattern.test( sanitized ) ? sanitized : null
        }
        catch {
            // Final fallback: very basic pattern
            const basicPattern = /^[+\d\s\-()]{7,20}$/
            return basicPattern.test( sanitized ) ? sanitized : null
        }
    },

    /**
     * Sanitize numeric strings
     */
    numeric: ( value: string ): string | null => {
        if ( typeof value !== "string" )
            return null

        const sanitized = sanitizeString( value, {
            allowHtml: false
        } )

        // Reject if sanitization removed dangerous content
        if ( sanitized !== value && value.includes( "<" ) ) {
            return null
        }

        return validator.isNumeric( sanitized ) ? sanitized : null
    },

    /**
     * Sanitize alphanumeric strings
     */
    alphanumeric: ( value: string ): string | null => {
        if ( typeof value !== "string" )
            return null

        const sanitized = sanitizeString( value, {
            allowHtml: false
        } )

        // Reject if sanitization removed dangerous content
        if ( sanitized !== value && value.includes( "<" ) ) {
            return null
        }

        return validator.isAlphanumeric( sanitized ) ? sanitized : null
    },
}

/**
 * Create a secure hash from sanitized parameters
 * This is useful for cache keys and other scenarios where you need a deterministic hash
 */
export const createSecureHash = (
    params: any,
    algorithm: "sha256" | "sha1" = "sha256",
): string => {
    const {
        createHash
    } = require( "node:crypto" )

    // Sanitize params first
    const sanitized = sanitizeParams( params )

    // Create deterministic serialization
    const serialized = JSON.stringify(
        sanitized,
        Object.keys( sanitized || {
        } ).sort(),
    )

    // Create hash
    return createHash( algorithm ).update( serialized ).digest( "hex" )
}

/**
 * Utility to check if a value is safe (doesn't contain dangerous patterns)
 */
export const isSafeValue = ( value: any ): boolean => {
    try {
        if ( typeof value === "string" ) {
            // Check for common XSS patterns
            const dangerousPatterns = [
                /<script/i,
                /javascript\s*:/i,
                /vbscript\s*:/i,
                /on\w+\s*=/i,
                /<iframe/i,
                /<object/i,
                /<embed/i,
                /<link/i,
                /<meta/i,
            ]

            return !dangerousPatterns.some( pattern => pattern.test( value ) )
        }

        if ( typeof value === "object" && value !== null ) {
            // Only check for actual prototype pollution, not normal objects
            return !hasPrototypePollution( value )
        }

        return true
    }
    catch {
        // If any error occurs during safety check, consider it unsafe
        return false
    }
}
