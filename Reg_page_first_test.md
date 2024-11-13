  ZAP Scanning Report   

# ZAP Scanning Report

Generated with [![The ZAP logo](Reg_page_first_test/zap32x32.png)ZAP](https://zaproxy.org) on Tue 12 Nov 2024, at 21:34:31

ZAP Version: 2.15.0

ZAP by [Checkmarx](https://checkmarx.com/)

## Contents

1.  [About this report](#about-this-report)
    1.  [Report parameters](#report-parameters)
*   [Summaries](#summaries)
    1.  [Alert counts by risk and confidence](#risk-confidence-counts)
    2.  [Alert counts by site and risk](#site-risk-counts)
    3.  [Alert counts by alert type](#alert-type-counts)
*   [Alerts](#alerts)
    1.  [Risk\=High, Confidence\=Medium (1)](#alerts--risk-3-confidence-2)
    2.  [Risk\=High, Confidence\=Low (1)](#alerts--risk-3-confidence-1)
    3.  [Risk\=Informational, Confidence\=Medium (1)](#alerts--risk-0-confidence-2)
*   [Appendix](#appendix)
    1.  [Alert types](#alert-types)

## About this report

### Report parameters

#### Contexts

No contexts were selected, so all contexts were included by default.

#### Sites

The following sites were included:

*   http://localhost:8000

(If no sites were selected, all sites were included by default.)

An included site must also be within one of the included contexts for its data to be included in the report.

#### Risk levels

Included: High, Medium, Low, Informational

Excluded: None

#### Confidence levels

Included: User Confirmed, High, Medium, Low

Excluded: User Confirmed, High, Medium, Low, False Positive

## Summaries

### Alert counts by risk and confidence

|     |     |     |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- |
This table shows the number of alerts for each level of risk and confidence included in the report.
(The percentages in brackets represent the count as a percentage of the total number of alerts included in the report, rounded to one decimal place.)
   
|     |     | Confidence |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- |
| User Confirmed | High | Medium | Low | Total |
| --- | --- | --- | --- | --- | --- | --- |
| Risk | High | 0  <br>(0.0%) | 0  <br>(0.0%) | 1  <br>(33.3%) | 1  <br>(33.3%) | 2  <br>(66.7%) |
| Medium | 0  <br>(0.0%) | 0  <br>(0.0%) | 0  <br>(0.0%) | 0  <br>(0.0%) | 0  <br>(0.0%) |
| Low | 0  <br>(0.0%) | 0  <br>(0.0%) | 0  <br>(0.0%) | 0  <br>(0.0%) | 0  <br>(0.0%) |
| Informational | 0  <br>(0.0%) | 0  <br>(0.0%) | 1  <br>(33.3%) | 0  <br>(0.0%) | 1  <br>(33.3%) |
| Total | 0  <br>(0.0%) | 0  <br>(0.0%) | 2  <br>(66.7%) | 1  <br>(33.3%) | 3  <br>(100%) |

### Alert counts by site and risk

|     |     |     |     |     |     |
| --- | --- | --- | --- | --- | --- |
This table shows, for each site for which one or more alerts were raised, the number of alerts raised at each risk level.
Alerts with a confidence level of "False Positive" have been excluded from these counts.
(The numbers in brackets are the number of alerts raised for the site at or above that risk level.)
  
|     |     | Risk |     |     |     |
| --- | --- | --- | --- | --- | --- |
| High  <br>(= High) | Medium  <br>(>= Medium) | Low  <br>(>= Low) | Informational  <br>(>= Informational) |
| --- | --- | --- | --- | --- | --- |
| Site | http://localhost:8000 | 2  <br>(2) | 0  <br>(2) | 0  <br>(2) | 1  <br>(3) |

### Alert counts by alert type

|     |     |     |
| --- | --- | --- |
This table shows the number of alerts of each alert type, together with the alert type's risk level.
(The percentages in brackets represent each count as a percentage, rounded to one decimal place, of the total number of alerts included in this report.)
| Alert type | Risk | Count |
| --- | --- | --- |
| [Path Traversal](#alert-type-0) | High | 1  <br>(33.3%) |
| [SQL Injection](#alert-type-1) | High | 1  <br>(33.3%) |
| [User Agent Fuzzer](#alert-type-2) | Informational | 12  <br>(400.0%) |
| Total |     | 3   |

## Alerts

1.  ### Risk\=High, Confidence\=Medium (1)
    
    1.  #### http://localhost:8000 (1)
        
        1.  ##### [SQL Injection](#alert-type-1) (1)
            
            1.  POST http://localhost:8000/register
                
                |     |     |
                | --- | --- |
                | Alert tags | *   [OWASP\_2017\_A01](https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html)<br>*   [OWASP\_2021\_A03](https://owasp.org/Top10/A03_2021-Injection/)<br>*   [CWE-89](https://cwe.mitre.org/data/definitions/89.html)<br>*   [WSTG-v42-INPV-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) |
                | Alert description | SQL injection may be possible. |
                | Other info | The page results were successfully manipulated using the boolean conditions \[ZAP AND 1=1 -- \] and \[ZAP AND 1=2 -- \]<br><br>The parameter value being modified was NOT stripped from the HTML output for the purposes of the comparison.<br><br>Data was returned for the original parameter.<br><br>The vulnerability was detected by successfully restricting the data originally returned, by manipulating the parameter. |
                | Request | Request line and header section (317 bytes)<br><br>```<br>POST http://localhost:8000/register HTTP/1.1<br>host: localhost:8000<br>user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0<br>pragma: no-cache<br>cache-control: no-cache<br>content-type: application/x-www-form-urlencoded<br>referer: http://localhost:8000/register<br>content-length: 79<br><br>```<br><br>Request body (79 bytes)<br><br>```<br>username=ZAP+AND+1%3D1+--+&password=ZAP&birthdate=2024-11-12&role=administrator<br>``` |
                | Response | Status line and header section (159 bytes)<br><br>```<br>HTTP/1.1 500 Internal Server Error<br>content-type: text/plain; charset=UTF-8<br>vary: Accept-Encoding<br>content-length: 25<br>date: Tue, 12 Nov 2024 19:28:46 GMT<br><br>```<br><br>Response body (25 bytes)<br><br>```<br>Error during registration<br>``` |
                | Parameter | ```<br>username<br>``` |
                | Attack | ```<br>ZAP AND 1=1 -- <br>``` |
                | Solution | Do not trust client side input, even if there is client side validation in place.<br><br>In general, type check all data on the server side.<br><br>If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'<br><br>If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.<br><br>If database Stored Procedures can be used, use them.<br><br>Do \*not\* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!<br><br>Do not create dynamic SQL queries using simple string concatenation.<br><br>Escape all data received from the client.<br><br>Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.<br><br>Apply the principle of least privilege by using the least privileged database user possible.<br><br>In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.<br><br>Grant the minimum database access that is necessary for the application. |
                
2.  ### Risk\=High, Confidence\=Low (1)
    
    1.  #### http://localhost:8000 (1)
        
        1.  ##### [Path Traversal](#alert-type-0) (1)
            
            1.  POST http://localhost:8000/register
                
                |     |     |
                | --- | --- |
                | Alert tags | *   [OWASP\_2021\_A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)<br>*   [CWE-22](https://cwe.mitre.org/data/definitions/22.html)<br>*   [WSTG-v42-ATHZ-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)<br>*   [OWASP\_2017\_A05](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html) |
                | Alert description | The Path Traversal attack technique allows an attacker access to files, directories, and commands that potentially reside outside the web document root directory. An attacker may manipulate a URL in such a way that the web site will execute or reveal the contents of arbitrary files anywhere on the web server. Any device that exposes an HTTP-based interface is potentially vulnerable to Path Traversal.<br><br>Most web sites restrict user access to a specific portion of the file-system, typically called the "web document root" or "CGI root" directory. These directories contain the files intended for user access and the executable necessary to drive web application functionality. To access files or execute commands anywhere on the file-system, Path Traversal attacks will utilize the ability of special-characters sequences.<br><br>The most basic Path Traversal attack uses the "../" special-character sequence to alter the resource location requested in the URL. Although most popular web servers will prevent this technique from escaping the web document root, alternate encodings of the "../" sequence may help bypass the security filters. These method variations include valid and invalid Unicode-encoding ("..%u2216" or "..%c0%af") of the forward slash character, backslash characters ("..\\") on Windows-based servers, URL encoded characters "%2e%2e%2f"), and double URL encoding ("..%255c") of the backslash character.<br><br>Even if the web server properly restricts Path Traversal attempts in the URL path, a web application itself may still be vulnerable due to improper handling of user-supplied input. This is a common problem of web applications that use template mechanisms or load static text from files. In variations of the attack, the original URL parameter value is substituted with the file name of one of the web application's dynamic scripts. Consequently, the results can reveal source code because the file is interpreted as text instead of an executable script. These techniques often employ additional special characters such as the dot (".") to reveal the listing of the current working directory, or "%00" NULL characters in order to bypass rudimentary file extension checks. |
                | Request | Request line and header section (317 bytes)<br><br>```<br>POST http://localhost:8000/register HTTP/1.1<br>host: localhost:8000<br>user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0<br>pragma: no-cache<br>cache-control: no-cache<br>content-type: application/x-www-form-urlencoded<br>referer: http://localhost:8000/register<br>content-length: 70<br><br>```<br><br>Request body (70 bytes)<br><br>```<br>username=register&password=ZAP&birthdate=2024-11-12&role=administrator<br>``` |
                | Response | Status line and header section (139 bytes)<br><br>```<br>HTTP/1.1 200 OK<br>content-type: text/plain;charset=UTF-8<br>vary: Accept-Encoding<br>content-length: 29<br>date: Tue, 12 Nov 2024 19:28:11 GMT<br><br>```<br><br>Response body (29 bytes)<br><br>```<br>User registered successfully!<br>``` |
                | Parameter | ```<br>username<br>``` |
                | Attack | ```<br>register<br>``` |
                | Solution | Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.<br><br>When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."<br><br>For filenames, use stringent allow lists that limit the character set to be used. If feasible, only allow a single "." character in the filename to avoid weaknesses, and exclude directory separators such as "/". Use an allow list of allowable file extensions.<br><br>Warning: if you attempt to cleanse your data, then do so that the end result is not in the form that can be dangerous. A sanitizing mechanism can remove characters such as '.' and ';' which may be required for some exploits. An attacker can try to fool the sanitizing mechanism into "cleaning" data into a dangerous form. Suppose the attacker injects a '.' inside a filename (e.g. "sensi.tiveFile") and the sanitizing mechanism removes the character resulting in the valid filename, "sensitiveFile". If the input data are now assumed to be safe, then the file may be compromised.<br><br>Inputs should be decoded and canonicalized to the application's current internal representation before being validated. Make sure that your application does not decode the same input twice. Such errors could be used to bypass allow list schemes by introducing dangerous inputs after they have been checked.<br><br>Use a built-in path canonicalization function (such as realpath() in C) that produces the canonical version of the pathname, which effectively removes ".." sequences and symbolic links.<br><br>Run your code using the lowest privileges that are required to accomplish the necessary tasks. If possible, create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations.<br><br>When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.<br><br>Run your code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by your software.<br><br>OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows you to specify restrictions on file operations.<br><br>This may not be a feasible solution, and it only limits the impact to the operating system; the rest of your application may still be subject to compromise. |
                
3.  ### Risk\=Informational, Confidence\=Medium (1)
    
    1.  #### http://localhost:8000 (1)
        
        1.  ##### [User Agent Fuzzer](#alert-type-2) (1)
            
            1.  POST http://localhost:8000/register
                
                |     |     |
                | --- | --- |
                | Alert tags |     |
                | Alert description | Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response. |
                | Request | Request line and header section (287 bytes)<br><br>```<br>POST http://localhost:8000/register HTTP/1.1<br>host: localhost:8000<br>user-agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)<br>pragma: no-cache<br>cache-control: no-cache<br>content-type: application/x-www-form-urlencoded<br>referer: http://localhost:8000/register<br>content-length: 65<br><br>```<br><br>Request body (65 bytes)<br><br>```<br>username=ZAP&password=ZAP&birthdate=2024-11-12&role=administrator<br>``` |
                | Response | Status line and header section (159 bytes)<br><br>```<br>HTTP/1.1 500 Internal Server Error<br>content-type: text/plain; charset=UTF-8<br>vary: Accept-Encoding<br>content-length: 25<br>date: Tue, 12 Nov 2024 19:27:34 GMT<br><br>```<br><br>Response body (25 bytes)<br><br>```<br>Error during registration<br>``` |
                | Parameter | ```<br>Header User-Agent<br>``` |
                | Attack | ```<br>Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)<br>``` |
                

## Appendix

### Alert types

This section contains additional information on the types of alerts in the report.

1.  #### Path Traversal
    
    |     |     |
    | --- | --- |
    | Source | raised by an active scanner ([Path Traversal](https://www.zaproxy.org/docs/alerts/6/)) |
    | CWE ID | [22](https://cwe.mitre.org/data/definitions/22.html) |
    | WASC ID | 33  |
    | Reference | 1.  [https://owasp.org/www-community/attacks/Path\_Traversal](https://owasp.org/www-community/attacks/Path_Traversal)<br>2.  [https://cwe.mitre.org/data/definitions/22.html](https://cwe.mitre.org/data/definitions/22.html) |
    
2.  #### SQL Injection
    
    |     |     |
    | --- | --- |
    | Source | raised by an active scanner ([SQL Injection](https://www.zaproxy.org/docs/alerts/40018/)) |
    | CWE ID | [89](https://cwe.mitre.org/data/definitions/89.html) |
    | WASC ID | 19  |
    | Reference | 1.  [https://cheatsheetseries.owasp.org/cheatsheets/SQL\_Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) |
    
3.  #### User Agent Fuzzer
    
    |     |     |
    | --- | --- |
    | Source | raised by an active scanner ([User Agent Fuzzer](https://www.zaproxy.org/docs/alerts/10104/)) |
    | Reference | 1.  [https://owasp.org/wstg](https://owasp.org/wstg) |