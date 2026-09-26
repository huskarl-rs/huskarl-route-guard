# Tomcat and Spring MVC fixture

Run `mise run test-tomcat-spring` from the repository root. Java and Maven run
inside Docker; no host JDK is needed. The same 7,024 paths, seven policy layouts,
and independent route-ID assertions used by the other fixtures apply here.

## Pinned environment

- Tomcat embedded core and annotations API 11.0.26.
- Spring Framework/MVC 7.0.8; every runtime JAR, including transitive dependencies,
  is recorded in `dependencies.sha256`. The image build compares the entire
  generated JAR checksum list, rejecting missing, extra, or changed artifacts.
- Maven 3.9.11 and Temurin Java 21 images are pinned by multi-platform digest.
  The runtime image reports Java 21.0.12.1. Both ARM64 and x86-64 images exist.
- Maven compiler, resources, and dependency plugin versions are explicit in
  `pom.xml`. Runtime dependency checksums do not cover Maven build-plugin JARs.

To update dependencies deliberately, edit the POM and build the `dependencies`
stage. Review its resolved JAR set before replacing the checksum file:

```sh
docker build --target dependencies -t route-guard-tomcat-dependencies tests/downstream/tomcat-spring
docker run --rm --entrypoint sh --workdir /fixture/target/dependency route-guard-tomcat-dependencies \
  -c 'LC_ALL=C sha256sum *.jar' > tests/downstream/tomcat-spring/dependencies.sha256
mise run test-tomcat-spring
```

## Routing configuration

`ROUTING_PROFILE=PathPattern` is required; unknown profiles fail startup. Tomcat's
HTTP connector explicitly uses UTF-8, rejects encoded `/`, decodes encoded `\`,
disallows backslash separators, and sets `rejectSuspiciousURIs=false`. The root
`DispatcherServlet` uses a case-sensitive Spring `PathPatternParser` with its
HTTP path parsing options. No fixture code decodes, truncates, or normalizes paths.

Native controller mappings provide admin, files, private, exact, parameterized,
and fallback route IDs. GET mappings also support HEAD. A parent `/files/**` POST
mapping serves the private child when its GET mapping does not match the method.
The unrestricted fallback serves other method gaps. As with Express, the guard
method layout needs an explicit private-child POST registration to retain that
availability. Removing HEAD or the child POST declaration must deny the named
request safely, without accepted-request policy confusion.

This is Spring MVC on embedded Tomcat, not a Spring Boot or Spring Security
configuration. Alternate servlet mappings, connector options, filters, and
`AntPathMatcher` remain outside this profile.

## Observed parsing distinctions

The harness pins these direct GET probes independently of guard acceptance:

| Request target | Status | Native route ID |
|---|---|---|
| `/admin;x=1/probe.txt` | 200 | `admin` |
| `/admin%3Bx=1/probe.txt` | 200 | `public` |
| `/public/..;x=1/admin/probe.txt` | 200 | `public` |
| `/admin%2fprobe.txt` | 400 | None |

In particular, servlet normalization alone does not predict the final Spring
handler for `..;`. The observations concern the complete pinned stack. These
probes are included in the full-corpus `characterization` rows in the TSV and do
not count as guard forwarding or policy agreement. The normal corpus run found zero policy
mismatches with `Sensitive`, `UpToOne`, and the default structural classes.

References: [Tomcat HTTP connector](https://tomcat.apache.org/tomcat-11.0-doc/config/http.html),
[Spring request mappings](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html).
