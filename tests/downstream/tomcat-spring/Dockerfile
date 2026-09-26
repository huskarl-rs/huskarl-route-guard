FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS dependencies
WORKDIR /fixture
COPY pom.xml ./
COPY src/ src/
RUN mvn --batch-mode --no-transfer-progress compile dependency:copy-dependencies -DincludeScope=runtime

FROM dependencies AS build
COPY dependencies.sha256 ./
RUN cd target/dependency && LC_ALL=C sha256sum *.jar | diff - /fixture/dependencies.sha256

FROM eclipse-temurin:21-jre@sha256:d7051a45dd955e4d5d1db4d3f4269fe13d1c6dff8cc6b7ef89fc8577b96c1982
WORKDIR /fixture
COPY --from=build /fixture/target/classes/ classes/
COPY --from=build /fixture/target/dependency/ dependency/
USER 10001:10001
CMD ["java", "-cp", "classes:dependency/*", "fixture.Server"]
