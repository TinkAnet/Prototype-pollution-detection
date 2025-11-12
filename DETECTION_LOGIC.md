# Detection Logic

How the detector finds prototype pollution vulnerabilities.

## What We Detect

### 1. Direct Dangerous Assignments

```javascript
obj.__proto__.polluted = "test";
```

**How**: Scans AST for assignments to `__proto__`, `constructor`, or `prototype`.  
**Severity**: HIGH

### 2. Unsafe Merge Functions

```javascript
function extend(out, src) {
    for (key in src) out[key] = src[key];  // No validation!
}
```

**How**: 
- Finds functions named `extend`, `merge`, `clone`, etc.
- Checks if function validates property names
- Looks for checks like `if (key === '__proto__')`

**Severity**: HIGH if no validation, MEDIUM if partial

### 3. HTML Injection Vectors

#### Data Attributes
```html
<img data-pace-options='{"__proto__": {"polluted": "test"}}'>
```

**How**:
- Extracts `data-*` attributes from HTML
- Parses JSON and checks for dangerous properties
- Also checks `id` and `name` attributes

**Severity**: HIGH

#### JSON.parse on DOM
```javascript
var data = JSON.parse(el.getAttribute("data-options"));
```

**How**: Detects `JSON.parse()` with DOM sources:
- `getAttribute()`, `dataset.*`
- `querySelector()`, `getElementById()`
- `localStorage`, `sessionStorage`
- `location.search`, `location.hash`

**Severity**: HIGH

#### Complete Chain
```javascript
var data = JSON.parse(el.getAttribute("data-options"));
extend({}, defaults, data);  // Complete attack chain
```

**How**: Tracks when JSON.parse results are merged.  
**Severity**: HIGH

## Attack Chain Detection

The detector finds complete attack chains:

1. HTML element with malicious data attribute
2. JavaScript retrieves from DOM
3. JSON.parse() without validation
4. Unsafe merge into objects
5. Prototype pollution achieved

## What Gets Flagged

- ✅ Direct `__proto__` assignments
- ✅ Unsafe extend/merge functions
- ✅ JSON.parse() on DOM attributes
- ✅ HTML data attributes with dangerous properties
- ✅ Complete HTML injection chains

## Limitations

- Static analysis only
- Pattern-based detection
- May have false positives/negatives
