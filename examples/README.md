# Prototype Pollution Detection Examples

This directory contains comprehensive test examples demonstrating source-to-sink data flow detection for prototype pollution vulnerabilities.

## Example Structure

Each example is a complete folder with:
- **Source files**: Contain user-controlled data entry points (JSON.parse, DOM attributes, etc.)
- **Sink files**: Contain vulnerable merge/extend functions
- **Main files**: Connect sources to sinks, demonstrating data flow

## Examples

### Example 1: Client-Side JSON.parse
**Location**: `example1_client_side_json_parse/`

- **Source**: JSON.parse from DOM attributes, localStorage, URL parameters
- **Sink**: Vulnerable extend/merge functions in separate file
- **Files**:
  - `index.html` - HTML page
  - `source.js` - Source extraction functions
  - `sink.js` - Vulnerable merge functions
  - `main.js` - Connects source to sink

**Test**: Open `index.html` in browser

### Example 2: Server-Side Node.js
**Location**: `example2_server_side_nodejs/`

- **Source**: JSON.parse from HTTP request body, query params, headers
- **Sink**: Server-side vulnerable merge functions
- **Files**:
  - `source.js` - Request parsing functions
  - `sink.js` - Vulnerable merge functions
  - `server.js` - HTTP server connecting source to sink
  - `package.json` - Node.js dependencies

**Test**: 
```bash
cd example2_server_side_nodejs
npm install
node server.js
curl -X POST http://localhost:3000 -H "Content-Type: application/json" -d '{"__proto__":{"polluted":"yes"}}'
```

### Example 3: Mixed HTML/JS
**Location**: `example3_mixed_html_js/`

- **Source**: Multiple DOM sources (getAttribute, dataset, querySelector)
- **Sink**: Multiple vulnerable functions
- **Files**:
  - `index.html` - HTML with inline scripts
  - `utils.js` - Source extraction utilities
  - `vulnerable.js` - Sink functions
  - Inline script in HTML connecting source to sink

**Test**: Open `index.html` in browser

### Example 4: DOM Chain
**Location**: `example4_dom_chain/`

- **Source**: Complex DOM queries (querySelectorAll, getElementById, dataset)
- **Sink**: Multiple merge functions
- **Files**:
  - `index.html` - HTML structure
  - `dom-source.js` - DOM source extraction
  - `merge-sink.js` - Sink functions
  - `app.js` - Application logic connecting sources to sinks

**Test**: Open `index.html` in browser

### Example 5: Express Server
**Location**: `example5_express_server/`

- **Source**: Express.js request data (body, query, headers, cookies)
- **Sink**: Server-side merge functions
- **Files**:
  - `source.js` - Express request parsing
  - `sink.js` - Vulnerable merge functions
  - `server.js` - Express server
  - `package.json` - Express dependencies

**Test**:
```bash
cd example5_express_server
npm install
node server.js
curl -X POST http://localhost:3000/api/config -H "Content-Type: application/json" -d '{"__proto__":{"polluted":"yes"}}'
```

## Expected Detection

The prototype pollution detector should identify:

1. **Sources**: 
   - JSON.parse() calls
   - DOM attribute access (getAttribute, dataset)
   - Query selectors (querySelector, querySelectorAll)
   - User input (form values)

2. **Sinks**:
   - Property assignments (`obj[key] = value`)
   - Object.assign() calls
   - For...in loops with property copying
   - Recursive merge functions

3. **Data Flow**:
   - Variables assigned from sources
   - Function parameters receiving source data
   - Source data reaching sink operations

4. **Vulnerabilities**:
   - Source-to-sink pollution (highest severity)
   - Vulnerable recursive merge (high severity)
   - Direct dangerous property assignment (high severity)

## Testing the Detector

Run the detector on each example:

```bash
# Analyze entire example directory
prototype-pollution-detector analyze examples/example1_client_side_json_parse/

# Analyze specific file
prototype-pollution-detector analyze examples/example1_client_side_json_parse/source.js

# Verbose output
prototype-pollution-detector analyze examples/example1_client_side_json_parse/ -v
```

Each example should produce vulnerabilities showing:
- Source location (file, line)
- Sink location (file, line)
- Data flow path (variable names)
- Vulnerability type and severity

