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
package com.sekai.app.controller.contact;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

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
package com.sekai.app.controller.contact;


import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

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
package com.sekai.app.controller.contact;

import com.sekai.app.waf.FrogWaf;
import lombok.SneakyThrows;
import lombok.val;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.nio.charset.Charset;
import java.nio.file.AccessDeniedException;
import java.util.Arrays;

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

## Challenge: Chunky (16 solves)

![](https://i.imgur.com/yWbxMYQ.png)

## References
* Team: [FireShell](https://fireshellsecurity.team/)
* [Team Twitter](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks)
* [Repo with artifacts discussed here](https://github.com/Neptunians/sekai-ctf-2023-web-writeup)
* [Team Project Sekai](https://sekai.team/)