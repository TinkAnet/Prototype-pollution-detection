//***************************************
// Copyright: CRM Together
// crmtogether.com
// Conditions of use are that we are credited with the code (or contribution) in a visible manner
//***************************************
// ======================================
//to run
//cscript "C:\Sage100Objects\Sage100Objects.js"
// ======================================

// ======================================
// Config: defaults + load from file
// ======================================
var CONFIG_DEFAULTS = {
  // Files
  csvPath:               "C:\\Sage100Objects\\csvfiles\\demo.csv",
  OutputFilePath: "C:\\Sage100Objects\\csvfiles\\arcustomer_update.csv",
  logFilePath:           "C:\\Sage100Objects\\logs\\import_log.txt",
  logMaxSizeBytes:       5 * 1024 * 1024,  // 5MB

  // Sage 100
  mas90Root:   "C:\\Sage\\Sage 100\\MAS90\\Home",
  company:     "ABC",
  user:        "john",
  password:    "demo2024",
  divisionNo:  "01", // default AR/AP division if absent in CSV
  salesperson: { divisionNo: "01", no: "0100" }
};
var CONFIG_PATH = "C:\\Sage100Objects\\arcustomer_import_config.json";

// ======================================
// Utilities
// ======================================
function randomDigits(maxLen) {
  var len = 1 + Math.floor(Math.random() * maxLen); // 1..maxLen
  var min = (len === 1) ? 0 : Math.pow(10, len - 1);
  var max = Math.pow(10, len) - 1;
  return String(min + Math.floor(Math.random() * (max - min + 1)));
}	
function randomAlnum(maxLen) {
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var len = 1 + Math.floor(Math.random() * maxLen); // 1..maxLen
  if (len<5) len=5;
  var s = "", i;
  for (i = 0; i < len; i++) {
    var idx = Math.floor(Math.random() * chars.length);
    s += chars.charAt(idx);
  }
  return s;
}
function _isEmpty(v){ return v===null || v===undefined || v===""; }
function _undefToBlank(v){ return (!v || (v+""=="undefined")) ? "" : v; }
function _alnum7Upper(s){ return (s||"").replace(/[^a-zA-Z0-9]/g,"").toUpperCase().substring(0,7); }
if (typeof JSON === "undefined") {
    JSON = {};
    JSON.parse = function (s) {
        return eval('(' + s + ')');
    };
}
function getTimestamp(){
  var now = new Date(); function pad2(n){return ("0"+n).slice(-2);}
  return now.getFullYear()+"-"+pad2(now.getMonth()+1)+"-"+pad2(now.getDate())
       +" "+pad2(now.getHours())+":"+pad2(now.getMinutes())+":"+pad2(now.getSeconds());
}
// Today as YYYYMMDD
function getTodayYYYYMMDD(d){
  function pad2(n){return ("0"+n).slice(-2);}
  return ""+d.getFullYear()+pad2(d.getMonth()+1)+pad2(d.getDate());
}

function deepMerge(target, src){
  if (!src) return target;
  for (var k in src) if (src.hasOwnProperty(k)){
    if (typeof src[k]==="object" && src[k]!==null && !(src[k] instanceof Array)){
      if (typeof target[k]!=="object" || target[k]===null) target[k]={};
      deepMerge(target[k], src[k]);
    } else target[k]=src[k];
  }
  return target;
}

// Trusted local JSON loader (JScript may lack JSON.parse)
function loadJsonFile(fso, path){
  if (!fso.FileExists(path)) return null;
  var fh = fso.OpenTextFile(path, 1); var txt = fh.ReadAll(); fh.Close();
  return eval("(" + txt + ")");
}

// Logging / Creatio output
var logFile = null;
function log(msg){
  var ts = getTimestamp();
  WScript.Echo(msg);
  if (logFile) logFile.WriteLine(ts + " - " + msg);
}
var OutputFile = null;
function outputforCreatio(Id, AlternativeName){
  // kept for AR_Customer echo compatibility
  WScript.Echo("outputforCreatio: " + AlternativeName);
  if (OutputFile) OutputFile.WriteLine(Id + "," + AlternativeName);
}

// ======================================
// Robust CSV parsing (RFC 4180-ish)
// ======================================
function csvRecordIsComplete(buffer){
  var i, count=0; for(i=0;i<buffer.length;i++){ if(buffer.charAt(i)==='"') count++; }
  return (count % 2) === 0; // even → balanced
}
function parseCsvRecord(record){
  var fields=[], cur="", inQuotes=false, i=0; record=record.replace(/\r\n/g,"\n").replace(/\r/g,"\n");
  while(i<record.length){
    var ch=record.charAt(i);
    if(inQuotes){
      if(ch === '"'){
        if(i+1<record.length && record.charAt(i+1)==='"'){ cur+='"'; i+=2; }
        else { inQuotes=false; i++; }
      } else { cur+=ch; i++; }
    } else {
      if(ch === '"'){ inQuotes=true; i++; }
      else if(ch === ','){ fields.push(cur); cur=""; i++; }
      else if(ch === '\n'){ i++; break; }
      else { cur+=ch; i++; }
    }
  }
  fields.push(cur);
  return fields;
}
function readCsvRecord(file){
  var buffer="", first=true;
  while(true){
    if(file.AtEndOfStream){ return buffer.length>0 ? buffer : null; }
    var line = file.ReadLine();
    if(!first) buffer+="\n";
    buffer+=line; first=false;
    if(csvRecordIsComplete(buffer)) return buffer;
  }
}

// ======================================
// record wrapper (entity registry)
// ======================================
// Each entity: { bus, module, task, key:[..], exists(bus,key){..}}
var SAGE100_ENTITIES = {
  "AR_Customer": {
    bus: "AR_Customer_bus",
    module: "A/R",
    task: "AR_Customer_UI",
    key: ["ARDivisionNo", "CustomerNo"],
	division_key: "ARDivisionNo",
	identity_key : "CustomerNo",
    exists: function(bus, key){
      bus.nSetKeyValue("ARDivisionNo$", key.ARDivisionNo);
      return bus.nFind(key.CustomerNo) === 1;
    }
  },
  "AR_CustomerContact": {
    bus: "AR_CustomerContact_bus",
    module: "A/R",
    task: "AR_CustomerContact_UI",
    key: ["ARDivisionNo", "CustomerNo", "ContactCode"],
    exists: function(bus, key){
      bus.nSetKeyValue("ARDivisionNo$", key.ARDivisionNo);
      bus.nSetKeyValue("CustomerNo$",   key.CustomerNo);
      return bus.nFind(key.ContactCode) === 1;
    }
  },
  "AP_Vendor": {
    bus: "AP_Vendor_bus",
    module: "A/P",
    task: "AP_Vendor_UI",
    key: ["APDivisionNo", "VendorNo"],
	division_key: "APDivisionNo",
	identity_key : "VendorNo",
    exists: function(bus, key){
      bus.nSetKeyValue("APDivisionNo$", key.APDivisionNo);
      return bus.nFind(key.VendorNo) === 1;
    }
  },
  "SO_SalesOrderHeader": {
    bus: "SO_SalesOrder_bus",
    module: "S/O",
    task: "SO_SalesOrder_UI",
    key: ["SalesOrderNo"],
	division_key: "ARDivisionNo",
	identity_key : "SalesOrderNo",
    exists: function(bus, key){
		bus.nSetKeyValue("SalesOrderNo$", key.SalesOrderNo);
      return bus.nFind(key.SalesOrderNo) === 1;
    }
  },
  "SO_SalesOrderDetail": {
    bus: "SO_SalesOrderDetail_bus",
    module: "S/O",
    task: "SO_SalesOrder_UI",
    key: ["SalesOrderNo", "LineKey"],
    exists: function(bus, key){
      bus.nSetKeyValue("SalesOrderNo$", key.SalesOrderNo);
      return bus.nFind(String(key.LineKey)) === 1;
    }
  },
  "AR_InvoiceHeader": {
    bus: "AR_InvoiceHeader_bus",
    module: "A/R",
    task: "AR_Invoice_UI",
    key: ["InvoiceNo"],
    exists: function(bus, key){
      return bus.nFind(key.InvoiceNo) === 1;
    }
  },
  "AR_InvoiceDetail": {
    bus: "AR_InvoiceDetail_bus",
    module: "A/R",
    task: "AR_Invoice_UI",
    key: ["InvoiceNo", "LineKey"],
    exists: function(bus, key){
      bus.nSetKeyValue("InvoiceNo$", key.InvoiceNo);
      return bus.nFind(String(key.LineKey)) === 1;
    }
  }
};

// ======================================
// Sage session helper (with simple module switch)
// ======================================
function SageSession(rootPath, company, user, password, dateYYYYMMDD){
  var oScript = new ActiveXObject("ProvideX.Script");
  log("Init ProvideX at: " + rootPath);
  oScript.Init(rootPath);

  var oSS = oScript.NewObject("SY_Session");
  if(!oSS) throw new Error("Unable to create SY_Session.");

  log("Logon: "      + oSS.nLogon());
  log("SetUser: "    + oSS.nSetUser(user, password));
  log("SetCompany: " + oSS.nSetCompany(company));
  log("SetDate: "    + oSS.nSetDate("A/R", dateYYYYMMDD)); // default date set on A/R
  log("SetModule: "  + oSS.nSetModule("A/R"));
  oSS.nSetProgram(oSS.nLookupTask("AR_Customer_UI"));

  this.script = oScript;
  this.session = oSS;

  this.ensureModule = function(modCode, taskUI){
    if (!modCode) return;
    try { oSS.nSetModule(modCode); } catch(e){}
    try { if (taskUI){ oSS.nSetProgram(oSS.nLookupTask(taskUI)); } } catch(e){}
  };
  this.dispose = function(){ try { oSS.nCleanup(); } catch(e){} };
}

function Sage100Record(entityName, session){
  var meta = SAGE100_ENTITIES[entityName];
  if(!meta) throw new Error("Unknown entity: " + entityName);

  session.ensureModule(meta.module, meta.task);

  this.oBus = session.script.NewObject(meta.bus, session.session);
  if(!this.oBus) throw new Error("Unable to create " + meta.bus);
  
  this.lineItems=[];//for sales orders

  var _key = {};
  var _fields = {};

  function setFieldNoDollar(name, value){
    _fields[name] = _undefToBlank(value);
  }

	this.SetKey = function(a, b){
	  if (typeof a === "string") {      // pair form: SetKey("Field","Value")
      _key[a] = b;
      return this;
	  }
	  var keyObj = a || {};             // object form: SetKey({Field:Value,...})
	  for (var i=0; i<meta.key.length; i++){
      var k = meta.key[i];
      if (keyObj.hasOwnProperty(k)) _key[k] = keyObj[k];
	  }
	  return this;
	};

  this.SaveHeader = function(){
    var ret = this.oBus.nWrite();
    if (ret !== 1) {
      log("SaveHeader failed: " + this.oBus.sLastErrorMsg);
    }    
    return this;
  };

  this.SetHeaderKey = function(a,b){
    var rv = this.oBus.nSetValue(a + "$",b);
    if (rv === 0) WScript.Echo("SetHeaderKey failed: " + this.oBus.sLastErrorMsg);
    return rv;
  };

  this.SetDateKey = function(a,b){
    log("SetDateKey: " + a + "$=" + b);
    this.oBus.nSetDate(a + "$", "S/O", b);
    return this;
  };

  this.SetTimeKey = function(a,b){
    var res = this.oBus.nSetValue(a + "$",b);
    if (res === 0) 
      WScript.Echo("SetTimeKey failed: " + this.oBus.sLastErrorMsg);
    else
      log("SetTimeKey success: " + a + "$=" + b);
    return this;
  };

  //
  this.SetNKey = function(a){
    var rv = this.oBus.nSetKey(a);
    if (rv === 0) 
      WScript.Echo("SetNKey failed: " + this.oBus.sLastErrorMsg);
    else
      log("SetNKey success: " + a);

    return rv; //SHOULD this not RETURN the result of nSetKey and not the Sage100Record object? 
  };

  //to do...allow this Set call to work for all fields...and it checks for $...dont rely on  the user
  this.Set = function(fieldNameNoDollar, value){
    setFieldNoDollar(fieldNameNoDollar, value);
    return this;
  };

  this.SetMany = function(obj){
    for (var k in obj) if (obj.hasOwnProperty(k)) setFieldNoDollar(k, obj[k]);
    return this;
  };


	  this.GetKey = function(){ var r={}; for(var k in _key) if(_key.hasOwnProperty(k)) r[k]=_key[k]; return r; };

	  this.test = function(){
      //THIS WORKS...might help sanity check things
      this.oBus.nSetKeyValue("ARDivisionNo$", "01");
      this.oBus.nSetKeyValue("CustomerNo$", "BRESLIX");
      this.oBus.nSetKey();
      
      this.oBus.nSetValue("SalespersonDivisionNo$", "01");
      this.oBus.nSetValue("SalespersonNo$", "0100");	
      this.oBus.nSetValue("CustomerName$", "test ABC");
      this.oBus.nSetValue("EmailAddress$", "test@test.com");
      this.oBus.nSetValue("AddressLine1$", "123 state");
      this.oBus.nSetValue("ZipCode$", "123456");
      this.oBus.nSetValue("State$", "CA");
      this.oBus.nSetValue("City$", "Los Angelas");

      // Write the record
      if (this.oBus.nWrite() !== 1) {
        log("Write failed for " + customerName +"("+ customerNo + "): " + oBus.sLastErrorMsg);
      }
	  }
    this.getBus=function(){
		return this.oBus;
	}
	
	this.AddLineItem=function(lineItemObj)
	{
		this.lineItems.push(lineItemObj);
	}
  
    this.SetLineItems = function(lineItemsCSVPath) {
        if (!fso.FileExists(lineItemsCSVPath)) {
            WScript.Echo("CSV not found: " + lineItemsCSVPath);
            WScript.Quit(1);
        }

        lineItemsSource = fso.OpenTextFile(lineItemsCSVPath, 1, false,-2);
        lineitems_headers = lineItemsSource.ReadLine().split(",");			
  
  
        while (!lineItemsSource.AtEndOfStream) {
          var line = lineItemsSource.ReadLine();
          var line_values = line.split(",");		
            
          var row_line = {};
          for (var i = 0; i < lineitems_headers.length; i++) {
            row_line[lineitems_headers[i]] = line_values[i];
          }
        
          var itemType = row_line["ItemType"];
          itemType = "5"; //miscelleanous item type

          var itemCode = row_line["Code"];
          var itemCodeDesc = row_line["Name"];
          var unitOfMeasure = row_line["UnitOfMeasure"];
          var quantityOrdered = new String(row_line["Quantity"]);
          var unitPrice = (row_line["Price"]);
         
		 var ret=1;
         // var ret = this.oBus.oLines.nAddLine();
		  log("aa");
	var lines = this.oBus.Lines;
	//if (!lines) fail("Could not access oBus lines object.");
		  log("a");
          if (ret === 0) 
            log("AddLine error: " + lines.sLastErrorMsg);
          log("a2");
          //ret=lines.nSetValue("ItemType$",itemType);
         // if (ret === 0) 
          //  log("SetValue ItemType error: " + lines.sLastErrorMsg);
          log("a3");
		   log("a3itemCode"+itemCode);
		    log("lines"+lines);
          ret=lines.nSetValue("ItemCode$", itemCode); 
		   log("a3zzz");
          if (ret === 0) 
            log("Set value ItemCode error: " + lines.sLastErrorMsg);
            log("a4");
          ret=lines.nSetValue("ItemCodeDesc$", itemCodeDesc);
          if (ret === 0) 
            log("SetValue ItemCodeDesc error: " + lines.sLastErrorMsg);
            log("a5");
          //ret=oBus.oLines.nSetValue("UnitOfMeasure$", unitOfMeasure);
          //if (ret === 0) log("SetValue error: " + oBus.oLines.sLastErrorMsg);
          //log("SetValue UnitOfMeasure success");
  log("a6");
          log("Setting WarehouseCode: 000 ");
		  var wh   = String("000");
          ret=lines.nSetValue("WarehouseCode$",wh);
          if (ret === 0) {
            log("ret: " + ret);
            log("SetValue WarehouseCode error: " + lines.sLastErrorMsg);
          }
            log("a7");
          quantityOrdered = parseFloat(quantityOrdered);
          log("Setting QuantityOrdered: " + quantityOrdered);
          ret=lines.nSetValue("QuantityOrdered", quantityOrdered);
          if (ret === 0) 
            log("SetValue QuantityOrdered error: " + lines.sLastErrorMsg);

          log("Setting unitPrice: " + unitPrice);
          ret=lines.nSetValue("UnitPrice", unitPrice);          
          if (ret === 0) 
            log("SetValue UnitPrice error: " + lines.sLastErrorMsg);
          
          ret = lines.nWrite();         
          if (ret === 0) 
            log("Line write error: " + lines.sLastErrorMsg);
          
        }
    }



    this.Find = function (criteria) {
      log("Find: criteria=" + criteria);
	  log("Find: entityName=" +entityName)
	  log(criteria.CustomerNo);
  // ---- normalize criteria ----
  // Accepts: {CustomerName:"ACME"} or {CustomerNo:"ABC123", ARDivisionNo:"01"} or string
  var f = null, v = null, exact = false;

  if (typeof criteria === "string") {
    // sensible defaults per entity
    if (entityName === "AR_Customer")
	{ 
		f = "CustomerName"; 
		v = criteria; 
		log(f+"====?=="+v);
	}
    else if (entityName === "AP_Vendor")
		{ f = "VendorName"; v = criteria; }
    else if (entityName === "SO_SalesOrderHeader") 
	{ f = "SalesOrderNo"; v = criteria; }
//  } else if (criteria && typeof criteria === "object") {
	  
  } else if (criteria && typeof criteria === "object") {
    for (var k in criteria) if (criteria.hasOwnProperty(k) && k !== "exact") 
	{ f = String(k); v = String(criteria[k]); break; }
    exact = !!criteria.exact;
  }
log("f: " + f);
  if (!f) {
	  log("No criteria field found");
	  return { ok:false, found:false, error:"No criteria field found" };
  }
  var cap = (v || "").toUpperCase();
log("cap: " + cap);
  // ---- Sequential search approach using VBScript shim functions ----
  // This approach uses VBScript shim functions for proper GetValue handling
  function performSequentialSearch(bus, entity, field, searchValue, exactMatch) {
    var rows = [];
    var searchUpper = searchValue.toUpperCase();
    log("searchUpper: " + searchUpper);
    // Use VBScript shim functions for proper GetValue handling
    if (BOI_GetValue) {
      //log("Using VBScript shim functions for data retrieval");
      var shimres = performSequentialSearchWithShims(bus, entity, field, searchValue, exactMatch);
	  log("shimres");
	  log(shimres);
	  log(shimres.length);
	  return shimres;
    } else {
      //log("VBScript shims not available, falling back to JavaScript approach");
    }
	
    log("searchUpper: " + searchUpper);    
    // Set up index for sequential scanning
    var indexSet = false;
    var indexes = [];
    
    if (entity === "AR_Customer") {
      indexes = ["kCustomerNo", "kCustomerName", "kARDivisionNoCustomerNo"];
    } else if (entity === "AP_Vendor") {
      indexes = ["kVendorNo", "kVendorName", "kAPDivisionNoVendorNo"];
    } else if (entity === "SO_SalesOrderHeader") {
      indexes = ["kSalesOrderNo", "kCustomerNoSalesOrderNo"];
    }
    log("indexes: " + indexes);
    // Try to set an index that works
    for (var i = 0; i < indexes.length; i++) {
      if (bus.nSetIndex(indexes[i]) === 1) {
        indexSet = true;
        break;
      }
    }
    log("indexSet: " + indexSet);
    if (!indexSet) {
      // Fallback: try to set any available index
      bus.nSetIndex("kCustomerNo");
    }
    log("indexSet: " + indexSet);
    // Start from beginning of records (like VBScript nMoveFirst)
    var found = bus.nMoveFirst();
    if (found !== 1) {
      // Alternative: try to find with empty key (like VBScript example)
      if (entity === "AR_Customer") {
        bus.nSetKeyValue("CustomerNo$", "");
      } else if (entity === "AP_Vendor") {
        bus.nSetKeyValue("VendorNo$", "");
      } else if (entity === "SO_SalesOrderHeader") {
        bus.nSetKeyValue("SalesOrderNo$", "");
      }
      found = bus.nFind();
    }
    log("found: " + found);
    if (found === 1) {
      log("Starting sequential scan - found first record");
      var recordCount = 0;
      // Scan through all records (like VBScript Do While loop)
	  var prevValue="";
	  var exitDo=false;
      do {
        recordCount++;
        //log("Processing record #" + recordCount);
        var currentValue = "";
        var record = {};
        var valObj = { value: "" }; // Object wrapper for pass-by-reference simulation
        
        // Get field values - try multiple approaches to match VBScript behavior
        if (entity === "AR_Customer") {
          var custName = "";
          var custNo = "";
          var custDiv = "";
          
          // Approach 1: Try nGetValue with simple string variables (like VBScript)
          try {
            var nameRet = bus.nGetValue("CustomerName$", custName);
            var noRet = bus.nGetValue("CustomerNo$", custNo);
			if (prevValue!=noRet){
				prevValue=noRet;
			}else{
				exitDo=true;
			}
            var divRet = bus.nGetValue("ARDivisionNo$", custDiv);
            log("nGetValue with strings - Name: '" + custName + "', No: '" + custNo + "', Div: '" + custDiv + "'");
            log("nGetValue returns - Name: " + nameRet + ", No: " + noRet + ", Div: " + divRet);
          } catch(e) {
            log("nGetValue with strings failed: " + e.message);
          }
          
          // Approach 2: If strings are still empty, try object wrapper
          if (!custName && !custNo && !custDiv) {
            try {
              custName = _s(bus, "CustomerName$", valObj) || "";
              custNo = _s(bus, "CustomerNo$", valObj) || "";
              custDiv = _s(bus, "ARDivisionNo$", valObj) || "";
              log("Object wrapper approach - Name: '" + custName + "', No: '" + custNo + "', Div: '" + custDiv + "'");
            } catch(e2) {
              log("Object wrapper approach failed: " + e2.message);
            }
          }
          
          // Approach 3: Try direct property access as last resort
          if (!custName && !custNo && !custDiv) {
            try {
              custName = bus.CustomerName$ || bus.CustomerName || "";
              custNo = bus.CustomerNo$ || bus.CustomerNo || "";
              custDiv = bus.ARDivisionNo$ || bus.ARDivisionNo || "";
              log("Direct property access - Name: '" + custName + "', No: '" + custNo + "', Div: '" + custDiv + "'");
            } catch(e3) {
              log("Direct property access failed: " + e3.message);
            }
          }
          
          if (field === "CustomerName") {
            currentValue = custName.toUpperCase();
          } else if (field === "CustomerNo") {
            currentValue = custNo.toUpperCase();
          } else if (field === "ARDivisionNo") {
            currentValue = custDiv.toUpperCase();
          } else {
            // Default to CustomerName for string searches
            currentValue = custName.toUpperCase();
          }
          
          record = {
            ARDivisionNo: custDiv,
            CustomerNo: custNo,
            CustomerName: custName
          };
          
        } else if (entity === "AP_Vendor") {
          // Try direct property access first
          var vendorName = "";
          var vendorNo = "";
          var vendorDiv = "";
          
          try {
            vendorName = bus.VendorName$ || bus.VendorName || "";
            vendorNo = bus.VendorNo$ || bus.VendorNo || "";
            vendorDiv = bus.APDivisionNo$ || bus.APDivisionNo || "";
			if (prevValue!=vendorNo){
				prevValue=vendorNo;
			}else{
				exitDo=true;
			}			
            log("Direct property access - VendorName: '" + vendorName + "', VendorNo: '" + vendorNo + "', Div: '" + vendorDiv + "'");
          } catch(e) {
            log("Direct property access failed: " + e.message);
            // Fallback to nGetValue
            vendorName = _s(bus, "VendorName$", valObj) || "";
            vendorNo = _s(bus, "VendorNo$", valObj) || "";
            vendorDiv = _s(bus, "APDivisionNo$", valObj) || "";
          }
          
          if (field === "VendorName") {
            currentValue = vendorName.toUpperCase();
          } else if (field === "VendorNo") {
            currentValue = vendorNo.toUpperCase();
          } else if (field === "APDivisionNo") {
            currentValue = vendorDiv.toUpperCase();
          } else {
            // Default to VendorName for string searches
            currentValue = vendorName.toUpperCase();
          }
          
          record = {
            APDivisionNo: vendorDiv,
            VendorNo: vendorNo,
            VendorName: vendorName
          };
          
        } else if (entity === "SO_SalesOrderHeader") {
          // Try direct property access first
          var soNo = "";
          var soCustNo = "";
          var soDiv = "";
          
          try {
            soNo = bus.SalesOrderNo$ || bus.SalesOrderNo || "";
            soCustNo = bus.CustomerNo$ || bus.CustomerNo || "";
            soDiv = bus.ARDivisionNo$ || bus.ARDivisionNo || "";
			if (prevValue!=soNo){
				prevValue=soNo;
			}else{
				exitDo=true;
			}				
            log("Direct property access - SO: '" + soNo + "', CustNo: '" + soCustNo + "', Div: '" + soDiv + "'");
          } catch(e) {
            log("Direct property access failed: " + e.message);
            // Fallback to nGetValue
            soNo = _s(bus, "SalesOrderNo$", valObj) || "";
            soCustNo = _s(bus, "CustomerNo$", valObj) || "";
            soDiv = _s(bus, "ARDivisionNo$", valObj) || "";
          }
          
          if (field === "SalesOrderNo") {
            currentValue = soNo.toUpperCase();
          } else if (field === "CustomerNo") {
            currentValue = soCustNo.toUpperCase();
          } else {
            // Default to SalesOrderNo for string searches
            currentValue = soNo.toUpperCase();
          }
          
          record = {
            SalesOrderNo: soNo,
            ARDivisionNo: soDiv,
            CustomerNo: soCustNo
          };
        }
        
        // Perform string comparison (like VBScript string comparison)
        //log("Field: " + field + ", CurrentValue: '" + currentValue + "', SearchValue: '" + searchUpper + "'");
        var matches = false;
        if (exactMatch) {
          matches = (currentValue === searchUpper);
          log("Exact match check: " + matches);
        } else {
          matches = (currentValue.indexOf(searchUpper) >= 0);
          //log("Partial match check 1: " + matches);
        }
        
        if (matches) {
         // log("MATCH FOUND! Adding record: " + JSON.stringify(record));
          rows.push(record);
        }
        
        // Move to next record (like VBScript nMoveNext)
      } while (!exitDo && bus.nMoveNext() === 1);
    }
    
    return rows;
  }


log("......................");
  // ---- Perform sequential search ----
  var searchResults = performSequentialSearch(this.oBus, entityName, f, v, exact);
  
  return { 
    ok: true, 
	entity:entityName,
	svalue:v,
    found: searchResults.length > 0, 
    records: searchResults, 
    indexUsed: "(sequential scan)", 
    fieldUsed: f + "$" 
  };
    };
    
// --- VBScript shim functions for proper GetValue handling ---
// These functions use VBScript to handle pass-by-reference correctly

// Global VBScript functions (these need to be defined at the global scope)
var BOI_GetValue, BOI_MoveFirst, BOI_MoveNext, BOI_SetIndex, BOI_SetKeyValue, BOI_Find;

// Initialize VBScript shim functions
function initializeVBScriptShims() {
  try {
    // Create VBScript engine for shim functions
    var vbEngine = new ActiveXObject("ScriptControl");
    vbEngine.Language = "VBScript";
    
    // Define VBScript shim functions
    var vbCode = 
      'Function BOI_GetValue(obj, fieldName)\n' +
      '  Dim tmp : tmp = ""\n' +
      '  Call obj.nGetValue(fieldName, tmp)\n' +
      '  BOI_GetValue = tmp\n' +
      'End Function\n' +
      '\n' +
      'Function BOI_MoveFirst(obj)\n' +
      '  BOI_MoveFirst = obj.nMoveFirst()\n' +
      'End Function\n' +
      '\n' +
      'Function BOI_MoveNext(obj)\n' +
      '  BOI_MoveNext = obj.nMoveNext()\n' +
      'End Function\n' +
      '\n' +
      'Function BOI_SetIndex(obj, indexName)\n' +
      '  BOI_SetIndex = obj.nSetIndex(indexName)\n' +
      'End Function\n' +
      '\n' +
      'Function BOI_SetKeyValue(obj, fieldName, value)\n' +
      '  BOI_SetKeyValue = obj.nSetKeyValue(fieldName, value)\n' +
      'End Function\n' +
      '\n' +
      'Function BOI_Find(obj)\n' +
      '  BOI_Find = obj.nFind()\n' +
      'End Function\n';
    
    vbEngine.AddCode(vbCode);
    
    // Expose functions globally
    BOI_GetValue = function(obj, fieldName) {
      return vbEngine.Run("BOI_GetValue", obj, fieldName);
    };
    
    BOI_MoveFirst = function(obj) {
      return vbEngine.Run("BOI_MoveFirst", obj);
    };
    
    BOI_MoveNext = function(obj) {
      return vbEngine.Run("BOI_MoveNext", obj);
    };
    
    BOI_SetIndex = function(obj, indexName) {
      return vbEngine.Run("BOI_SetIndex", obj, indexName);
    };
    
    BOI_SetKeyValue = function(obj, fieldName, value) {
      return vbEngine.Run("BOI_SetKeyValue", obj, fieldName, value);
    };
    
    BOI_Find = function(obj) {
      return vbEngine.Run("BOI_Find", obj);
    };
    
    log("VBScript shim functions initialized successfully");
    return true;
  } catch(e) {
    log("Failed to initialize VBScript shims: " + e.message);
    return false;
  }
}

// Initialize shims when the script loads
if (!BOI_GetValue) {
  initializeVBScriptShims();
}

// Sequential search using VBScript shim functions
function performSequentialSearchWithShims(bus, entity, field, searchValue, exactMatch) {
  var rows = [];
  var searchUpper = searchValue.toUpperCase();
  
  try {
    // Set up index for sequential scanning
    var indexSet = false;
    var indexes = [];
    
    if (entity === "AR_Customer") {
      indexes = ["kCustomerNo", "kCustomerName", "kARDivisionNoCustomerNo"];
    } else if (entity === "AP_Vendor") {
      indexes = ["kVendorNo", "kVendorName", "kAPDivisionNoVendorNo"];
    } else if (entity === "SO_SalesOrderHeader") {
      indexes = ["kSalesOrderNo", "kCustomerNoSalesOrderNo"];
    }
    
    // Try to set an index that works
    for (var i = 0; i < indexes.length; i++) {
      if (BOI_SetIndex(bus, indexes[i]) === 1) {
        indexSet = true;
        log("Set index: " + indexes[i]);
        break;
      }
    }
    
    if (!indexSet) {
      // Fallback: try to set any available index
      BOI_SetIndex(bus, "kCustomerNo");
    }
    
    // Start from beginning of records (like VBScript nMoveFirst)
    var found = BOI_MoveFirst(bus);
    log("MoveFirst result: " + found);
    
    if (found !== 1) {
      // Alternative: try to find with empty key (like VBScript example)
      if (entity === "AR_Customer") {
        BOI_SetKeyValue(bus, "CustomerNo$", "");
      } else if (entity === "AP_Vendor") {
        BOI_SetKeyValue(bus, "VendorNo$", "");
      } else if (entity === "SO_SalesOrderHeader") {
        BOI_SetKeyValue(bus, "SalesOrderNo$", "");
      }
      found = BOI_Find(bus);
      log("Find with empty key result: " + found);
    }
    
    if (found === 1) {
      //log("Starting sequential scan with VBScript shims");
      var recordCount = 0;
	  var prevValue="";
      var exitDo=false;
      // Scan through all records (like VBScript Do While loop)
      do {
        recordCount++;
        //log("Processing record #" + recordCount);
        
        var currentValue = "";
        var record = {};
        
        // Get field values using VBScript shim functions
        if (entity === "AR_Customer") {
          var custName = BOI_GetValue(bus, "CustomerName$");
          var custNo = BOI_GetValue(bus, "CustomerNo$");
          var custDiv = BOI_GetValue(bus, "ARDivisionNo$");
			if (prevValue!=custNo){
				prevValue=custNo;
			}else{
				exitDo=true;
			}          
          //log("VBScript shim - Name: '" + custName + "', No: '" + custNo + "', Div: '" + custDiv + "'");
          
          if (field === "CustomerName") {
            currentValue = custName.toUpperCase();
          } else if (field === "CustomerNo") {
            currentValue = custNo.toUpperCase();
          } else if (field === "ARDivisionNo") {
            currentValue = custDiv.toUpperCase();
          } else {
            // Default to CustomerName for string searches
            currentValue = custName.toUpperCase();
          }
          
          record = {
            ARDivisionNo: custDiv,
            CustomerNo: custNo,
            CustomerName: custName
          };
          
        } else if (entity === "AP_Vendor") {
          var vendorName = BOI_GetValue(bus, "VendorName$");
          var vendorNo = BOI_GetValue(bus, "VendorNo$");
          var vendorDiv = BOI_GetValue(bus, "APDivisionNo$");
			if (prevValue!=vendorNo){
				prevValue=vendorNo;
			}else{
				exitDo=true;
			}             
          //log("VBScript shim - VendorName: '" + vendorName + "', VendorNo: '" + vendorNo + "', Div: '" + vendorDiv + "'");
          
          if (field === "VendorName") {
            currentValue = vendorName.toUpperCase();
          } else if (field === "VendorNo") {
            currentValue = vendorNo.toUpperCase();
          } else if (field === "APDivisionNo") {
            currentValue = vendorDiv.toUpperCase();
          } else {
            // Default to VendorName for string searches
            currentValue = vendorName.toUpperCase();
          }
          
          record = {
            APDivisionNo: vendorDiv,
            VendorNo: vendorNo,
            VendorName: vendorName
          };
          
        } else if (entity === "SO_SalesOrderHeader") {
          var soNo = BOI_GetValue(bus, "SalesOrderNo$");
          var soCustNo = BOI_GetValue(bus, "CustomerNo$");
          var soDiv = BOI_GetValue(bus, "ARDivisionNo$");
			if (prevValue!=soNo){
				prevValue=soNo;
			}else{
				exitDo=true;
			}               
          //log("VBScript shim - SO: '" + soNo + "', CustNo: '" + soCustNo + "', Div: '" + soDiv + "'");
          
          if (field === "SalesOrderNo") {
            currentValue = soNo.toUpperCase();
          } else if (field === "CustomerNo") {
            currentValue = soCustNo.toUpperCase();
          } else {
            // Default to SalesOrderNo for string searches
            currentValue = soNo.toUpperCase();
          }
          
          record = {
            SalesOrderNo: soNo,
            ARDivisionNo: soDiv,
            CustomerNo: soCustNo
          };
        }
        
        // Perform string comparison (like VBScript string comparison)
        //log("Field: " + field + ", CurrentValue: '" + currentValue + "', SearchValue: '" + searchUpper + "'");
        var matches = false;
        if (exactMatch) {
          matches = (currentValue === searchUpper);
          log("Exact match check: " + matches);
        } else {
          matches = (currentValue.indexOf(searchUpper) >= 0);
          //log("Partial match check 2: " + matches);
        }
        
        if (matches) {
          //log("MATCH FOUND! Adding record: " + JSON.stringify(record));
          rows.push(record);
		  break;
        }
        
        // Move to next record (like VBScript nMoveNext)
      } while (!exitDo && BOI_MoveNext(bus) === 1);
    }
    
    //log("VBScript shim search completed, found " + rows.length + " records");
    return rows;
    
  } catch(e) {
    log("VBScript shim search error: " + e.message);
    return [];
  }
}

function generateVBScriptContent(entity, field, searchValue, exactMatch, outputFile) {
  var content = 'Option Explicit\n\n';
  content += 'Dim oPVX, oSS, oBus, ret, hBus\n';
  content += 'Dim outputFile, fso\n\n';
  content += 'Set fso = CreateObject("Scripting.FileSystemObject")\n';
  content += 'Set outputFile = fso.CreateTextFile("' + outputFile + '", True)\n\n';
  content += 'Set oPVX = CreateObject("ProvideX.Script")\n';
  content += 'oPVX.Init "C:\\Sage\\Sage 100\\MAS90\\Home"\n\n';
  content += 'Set oSS = oPVX.NewObject("SY_Session")\n';
  content += 'ret = oSS.nLogon()\n';
  content += 'ret = oSS.nSetUser("john", "demo2024")\n';
  content += 'ret = oSS.nSetCompany("ABC")\n';
  
  if (entity === "AR_Customer") {
    content += 'ret = oSS.nSetDate("A/R", "20250101")\n';
    content += 'ret = oSS.nSetModule("A/R")\n';
    content += 'Set oBus = oPVX.NewObject("AR_Customer_bus", oSS)\n';
    content += 'ret = oBus.nSetIndex("kCustomerNo")\n';
  } else if (entity === "AP_Vendor") {
    content += 'ret = oSS.nSetDate("A/P", "20250101")\n';
    content += 'ret = oSS.nSetModule("A/P")\n';
    content += 'Set oBus = oPVX.NewObject("AP_Vendor_bus", oSS)\n';
    content += 'ret = oBus.nSetIndex("kVendorNo")\n';
  } else if (entity === "SO_SalesOrderHeader") {
    content += 'ret = oSS.nSetDate("S/O", "20250101")\n';
    content += 'ret = oSS.nSetModule("S/O")\n';
    content += 'Set oBus = oPVX.NewObject("SO_SalesOrder_bus", oSS)\n';
    content += 'ret = oBus.nSetIndex("kSalesOrderNo")\n';
  }
  
  content += '\nret = oBus.nMoveFirst()\n';
  content += 'If ret <> 1 Then\n';
  content += '  oBus.nSetKeyValue("' + getKeyField(entity) + '$", "")\n';
  content += '  ret = oBus.nFind()\n';
  content += 'End If\n\n';
  
  content += 'Do While ret = 1\n';
  content += '  Dim fieldValue, matches\n';
  content += '  fieldValue = ""\n';
  content += '  oBus.nGetValue("' + field + '$", fieldValue)\n';
  content += '  \n';
  content += '  matches = False\n';
  if (exactMatch) {
    content += '  If UCase(fieldValue) = UCase("' + searchValue + '") Then matches = True\n';
  } else {
    content += '  If InStr(UCase(fieldValue), UCase("' + searchValue + '")) > 0 Then matches = True\n';
  }
  content += '  \n';
  content += '  If matches Then\n';
  content += '    Dim recordData\n';
  content += '    recordData = ""\n';
  
  if (entity === "AR_Customer") {
    content += '    Dim div, no, name\n';
    content += '    oBus.nGetValue("ARDivisionNo$", div)\n';
    content += '    oBus.nGetValue("CustomerNo$", no)\n';
    content += '    oBus.nGetValue("CustomerName$", name)\n';
    content += '    outputFile.WriteLine div & "," & no & "," & name\n';
  } else if (entity === "AP_Vendor") {
    content += '    Dim div, no, name\n';
    content += '    oBus.nGetValue("APDivisionNo$", div)\n';
    content += '    oBus.nGetValue("VendorNo$", no)\n';
    content += '    oBus.nGetValue("VendorName$", name)\n';
    content += '    outputFile.WriteLine div & "," & no & "," & name\n';
  } else if (entity === "SO_SalesOrderHeader") {
    content += '    Dim so, div, cust\n';
    content += '    oBus.nGetValue("SalesOrderNo$", so)\n';
    content += '    oBus.nGetValue("ARDivisionNo$", div)\n';
    content += '    oBus.nGetValue("CustomerNo$", cust)\n';
    content += '    outputFile.WriteLine so & "," & div & "," & cust\n';
  }
  
  content += '  End If\n';
  content += '  ret = oBus.nMoveNext()\n';
  content += 'Loop\n\n';
  content += 'outputFile.Close\n';
  content += 'oSS.nCleanup\n';
  content += 'Set oBus = Nothing\n';
  content += 'Set oSS = Nothing\n';
  content += 'Set oPVX = Nothing\n';
  
  return content;
}

function getKeyField(entity) {
  if (entity === "AR_Customer") return "CustomerNo";
  if (entity === "AP_Vendor") return "VendorNo";
  if (entity === "SO_SalesOrderHeader") return "SalesOrderNo";
  return "CustomerNo";
}

// --- Dump a field safely (JScript cannot use GetValue ByRef)
// Using object wrapper to simulate pass-by-reference

function _s(o, f, valObj){ try { 
  // JavaScript doesn't handle pass-by-reference the same as VBScript
  // Try different approaches to get the field value
  
  // Method 1: Try nGetValue with proper object reference
  var result = o.nGetValue(f, valObj);
  log("nGetValue(" + f + ") result: " + result);
  log("valObj.value after nGetValue: " + valObj.value);
  
  // Method 2: Try using the object properties directly
  if (valObj.value !== undefined && valObj.value !== null && valObj.value !== "") {
    log("Using valObj.value: " + valObj.value);
    return String(valObj.value);
  }
  
  // Method 3: Try alternative property names that might be set
  if (valObj[f] !== undefined && valObj[f] !== null && valObj[f] !== "") {
    log("Using valObj[" + f + "]: " + valObj[f]);
    return String(valObj[f]);
  }
  
  // Method 4: Try using the return value directly (some implementations return the value)
  if (result && typeof result === "string" && result !== "1" && result !== "0") {
    log("Using return value as string: " + result);
    return result;
  }
  
  // Method 5: Try other GetValue methods
  try {
    if (o.GetValue) {
      var getResult = o.GetValue(f);
      if (getResult && getResult !== "0") {
        log("Using GetValue: " + getResult);
        return getResult;
      }
    }
  } catch(e2) {
    log("GetValue failed: " + e2.message);
  }
  
  // Method 6: Try sGetValue if available
  try {
    if (o.sGetValue) {
      var sResult = o.sGetValue(f);
      if (sResult && sResult !== "0") {
        log("Using sGetValue: " + sResult);
        return sResult;
      }
    }
  } catch(e3) {
    log("sGetValue failed: " + e3.message);
  }
  
  log("All methods failed for field: " + f);
  return "";
} catch(e){ 
  log("_s function error for " + f + ": " + e.message);
  return ""; 
} }


// --- Try to set an index, log if it exists
function _tryIndex(oBus, idx){
  var ok = oBus.nSetIndex(idx);
  log("nSetIndex('" + idx + "') => " + ok);
  return ok === 1;
}

// --- Single row logger
function _logRow(cust){
  var valObj = { value: "" };  // Wrap value in object for pass-by-reference simulation
  var div = _s(cust, "ARDivisionNo$", valObj);
  var no  = _s(cust, "CustomerNo$", valObj);
  var nm  = _s(cust, "CustomerName$", valObj);
  log("Row: " + div + "-" + no + " | " + nm);
}

// --- Browse runner (returns number of rows read)
function _runBrowse(oBus, filter, maxRows){
  // Try browse filter first
  var set = oBus.nSetBrowseFilter(filter||"");
  log("nSetBrowseFilter('" + (filter||"") + "') => " + set + "  msg=" + (oBus.sLastErrorMsg||""));
  
  if (set === 1) {
    var br = oBus.nBrowse();
    log("nBrowse() => " + br + "  msg=" + (oBus.sLastErrorMsg||""));
    if (br === 1) {
      var count = 0;
      while (oBus.nGetNextBrowseRow() === 1) {
        _logRow(oBus);
        count++;
        if (count >= (maxRows||10)) break;
      }
      oBus.nEndBrowse();
      log("nEndBrowse()");
      return count;
    }
  }
  
  // If browse filter fails, fall back to sequential scan
  log("Browse filter failed, falling back to sequential scan");
  var count = 0;
  var moved = oBus.nMoveFirst();
  if (moved !== 1) {
    oBus.nSetKeyValue("CustomerNo$", "");
    moved = oBus.nFind();
  }
  
  if (moved === 1) {
    do {
      _logRow(oBus);
      count++;
      if (count >= (maxRows||10)) break;
    } while (oBus.nMoveNext() === 1);
  }
  
  return count;
}

  	
  this.Delete =function(key){
    var ret = this.oBus.nSetKey(key); // use full SO number
  if (ret > 0) {
      ret = this.oBus.nDelete();
      if (ret === 0) {
          WScript.Echo("Delete failed: " + this.oBus.sLastErrorMsg);
      } else {
          WScript.Echo("Sales Order deleted.");
      }
  } else {
      WScript.Echo("SetKey failed: " + this.oBus.sLastErrorMsg);
  }
  };


  this.WriteRecord = function() {
    var ret = this.oBus.nWrite();
    if (ret !== 1) {
      log("WriteRecord failed: " + this.oBus.sLastErrorMsg);
      return { ok:false, error:this.oBus.sLastErrorMsg, key:this.GetKey() };
    }
    log("WriteRecord success");
    return { ok:true, action:"save", key:this.GetKey() };
  };


  this.Save = function() {
	  
	  var _action="";
 
    

    for (var f in _fields) if (_fields.hasOwnProperty(f)){
      var v = _fields[f]; 
      if (!_isEmpty(v)) 
      {
        log("setting:"+f+"="+v);
        this.oBus.nSetValue(f + "$", v);
      }
    }
		  	  log("this.lineItems.length: " + this.lineItems.length);
	if (this.lineItems.length > 0)
	{
		for (var i = 0; i < this.lineItems.length; i++) {
			var lineItem = this.lineItems[i];
			
			var lines = this.oBus.olines;
			// log("lineItem "+i+ ":"+ lineItem);
			 // log("lines "+i+ ":"+ lines);
			// Add a new line
			var ret = lines.nAddLine();
		//	if (ret === 0) {
			//	log("AddLine error: " + lines.sLastErrorMsg);
			//	continue;
			//}
			// log("lineItem "+i+ ":"+ lineItem);
			//log("lineItem ItemCode$ "+ lineItem["ItemCode$"]);
			
			// Set values for this line item
			for (var field in lineItem) {
				log("field:"+field);
				if (lineItem.hasOwnProperty(field)) {
					var value = lineItem[field];
					if (!_isEmpty(value)) {
						log("setting line item " + i + " " + field + "=" + value);
						ret=lines.nSetValue(field, value);
            if (ret === 0) {
              log("SetValue error: " + lines.sLastErrorMsg);
            } else {
              log("SetValue success: " + field + "=" + value);
            }
					}
				}
			}
			
			// Write the line
			ret = lines.nWrite();
			if (ret === 0) {
				log("Line write error: " + lines.sLastErrorMsg);
			}
		}
	}
	  
  
   

	  this.lineItems=[];//reset any line items
    var ok = this.oBus.nWrite();
    if (ok !== 1){
      log("Write failed: " + this.oBus.sLastErrorMsg);
      return { ok:false, error:this.oBus.sLastErrorMsg, key:this.GetKey() };
    } else {
      log("Write success");
      return { ok:true,action:_action, key:this.GetKey() };
    }
    
    //return { ok:true,action:_action, key:this.GetKey() };
  };

  // --- Public: call this to verify you can get rows and test filters
  this.Debug_AR_Customer = function(){
    log("=== DEBUG AR_Customer START ===");

    // Test 1: Find all customers using the new FIND function
    log("=== Test 1: Finding all customers using FIND function ===");
    var allCustomers = this.Find("");
    log("FIND function result: " + (allCustomers.ok ? "SUCCESS" : "FAILED"));
    log("Found " + (allCustomers.records ? allCustomers.records.length : 0) + " customers");
    
    if (allCustomers.found && allCustomers.records) {
      log("First 5 customers found:");
      for (var i = 0; i < Math.min(5, allCustomers.records.length); i++) {
        var cust = allCustomers.records[i];
        log("  " + (i+1) + ". " + cust.ARDivisionNo + "-" + cust.CustomerNo + " | " + cust.CustomerName);
      }
    }

    // Test 2: Search by customer name (partial match)
    log("=== Test 2: Searching by customer name (partial match) ===");
    var nameSearch = this.Find("Smyth Education");
    log("Name search for 'Smyth Education': " + (nameSearch.ok ? "SUCCESS" : "FAILED"));
    log("Found " + (nameSearch.records ? nameSearch.records.length : 0) + " customers with 'Test' in name");
    
    if (nameSearch.found && nameSearch.records) {
      for (var i = 0; i < nameSearch.records.length; i++) {
        var cust = nameSearch.records[i];
        log("  " + (i+1) + ". " + cust.ARDivisionNo + "-" + cust.CustomerNo + " | " + cust.CustomerName);
      }
    }

    // Test 3: Search by customer number (exact match)
    log("=== Test 3: Searching by customer number (exact match) ===");
    var numberSearch = this.Find({CustomerNo: "SHEPARD", exact: true});
    log("Number search for 'SHEPARD': " + (numberSearch.ok ? "SUCCESS" : "FAILED"));
    log("Found " + (numberSearch.records ? numberSearch.records.length : 0) + " customers with number 'SHEPARD'");
    
    if (numberSearch.found && numberSearch.records) {
      for (var i = 0; i < numberSearch.records.length; i++) {
        var cust = numberSearch.records[i];
        log("  " + (i+1) + ". " + cust.ARDivisionNo + "-" + cust.CustomerNo + " | " + cust.CustomerName);
      }
    }

    // Test 4: Search by division
    log("=== Test 4: Searching by division ===");
    var divisionSearch = this.Find({ARDivisionNo: "01"});
    log("Division search for '01': " + (divisionSearch.ok ? "SUCCESS" : "FAILED"));
    log("Found " + (divisionSearch.records ? divisionSearch.records.length : 0) + " customers in division '01'");
    
    if (divisionSearch.found && divisionSearch.records) {
      for (var i = 0; i < Math.min(3, divisionSearch.records.length); i++) {
        var cust = divisionSearch.records[i];
        log("  " + (i+1) + ". " + cust.ARDivisionNo + "-" + cust.CustomerNo + " | " + cust.CustomerName);
      }
    }

    // Test 5: If no customers found, test customer creation
    var totalCustomers = (allCustomers.records ? allCustomers.records.length : 0);
    if (totalCustomers === 0) {
      log("=== Test 5: No existing customers found - testing customer creation ===");
      
      // Try to create a test customer using the Save method
      this.SetKey({ARDivisionNo: "01", CustomerNo: "TEST001"});
      this.SetMany({
        CustomerName: "Test Customer",
        SalespersonDivisionNo: "01",
        SalespersonNo: "0100",
        EmailAddress: "test@example.com",
        AddressLine1: "123 Test Street",
        City: "Test City",
        State: "TS",
        ZipCode: "12345"
      });
      
      var saveResult = this.Save();
      log("Test customer creation result: " + (saveResult.ok ? "SUCCESS" : "FAILED"));
      
      if (saveResult.ok) {
        log("SUCCESS: Test customer created successfully");
        
        // Now try to find it using FIND function
        var findCreated = this.Find({CustomerNo: "TEST001", exact: true});
        log("Test customer find result: " + (findCreated.ok ? "SUCCESS" : "FAILED"));
        
        if (findCreated.found && findCreated.records) {
          var cust = findCreated.records[0];
          log("SUCCESS: Test customer found: " + cust.ARDivisionNo + "-" + cust.CustomerNo + " | " + cust.CustomerName);
        }
      } else {
        log("ERROR: Test customer creation failed: " + (saveResult.error || "Unknown error"));
      }
    } else {
      log("=== Test 5: Skipped - " + totalCustomers + " existing customers found ===");
    }

    // Summary
    log("=== DEBUG SUMMARY ===");
    log("Total customers found: " + totalCustomers);
    log("FIND function working: " + (allCustomers.ok ? "YES" : "NO"));
    log("Sequential search method: " + (allCustomers.indexUsed || "Unknown"));
    
    log("=== DEBUG AR_Customer END ===");
  };

  return this;
}



function getArg(args, name, defaultValue) {
    if (args.Exists(name)) {
        return args.Item(name);
    }
    return defaultValue;
}
function pad2(n) { 
  return (n < 10 ? "0" : "") + n; 
}

function generateCustomerNo(name) {
  if (!name) {
    throw new Error("Both code and name are required");
  }

  //log("generateCustomerNo: " + code + " " + name);
  var cleanName = name
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")   // keep only letters/numbers
    .substring(0, 6);            // limit length (ERP systems often cap at ~6 chars)



  //log("cleanName: " + cleanName);
  // Pad with zeros if too short
  var padded = padEnd(cleanName, 7, "0");
  //log("padded: " + padded);
  // Add random 3-digit sequence to avoid collisions
  var seq = Math.floor(Math.random() * 900 + 100); // 100–999
  //log("seq: " + seq);
  // Build CustomerNo
  return padded;
}

function padEnd(str, targetLength, padString) {
  var str = new String(str);
  //log("str: " + str);
  var padString = new String(padString || ' ');
  targetLength = targetLength >> 0; // ensure integer
  //log("targetLength: " + targetLength);
  if (str.length >= targetLength) {
    return str;
  }
  //log("str.length: " + str.length);
  var needed = targetLength - str.length;
  var padding = ''; 
  //log("needed: " + needed);
  while (padding.length < needed) {
    padding += padString;
  }
  //log("padding: " + padding);
  return str + padding.slice(0, needed);
}


function parseDateTime(dateTimeStr) {
  // "10/2/2024 5:26:49 PM" -> interpreted in local timezone
  return new Date(dateTimeStr);
}