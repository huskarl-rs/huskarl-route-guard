package fixture;

import java.nio.file.Files;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.util.ServerInfo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.SpringVersion;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.util.pattern.PathPatternParser;

public class Server {
    public static void main(String[] args) throws Exception {
        if (!"PathPattern".equals(System.getenv("ROUTING_PROFILE"))) {
            throw new IllegalArgumentException("Expected ROUTING_PROFILE=PathPattern");
        }
        var tomcat = new Tomcat();
        tomcat.setBaseDir(Files.createTempDirectory("tomcat-base").toString());
        tomcat.setPort(8080);
        var connector = tomcat.getConnector();
        connector.setURIEncoding("UTF-8");
        connector.setEncodedSolidusHandling("reject");
        connector.setEncodedReverseSolidusHandling("decode");
        connector.setAllowBackslash(false);
        connector.setRejectSuspiciousURIs(false);
        var context = tomcat.addContext("", Files.createTempDirectory("tomcat-docroot").toString());
        context.setParentClassLoader(Server.class.getClassLoader());
        var spring = new AnnotationConfigWebApplicationContext();
        spring.register(Mvc.class);
        var servlet = Tomcat.addServlet(context, "spring", new DispatcherServlet(spring));
        servlet.setLoadOnStartup(1);
        context.addServletMappingDecoded("/", "spring");
        tomcat.start();
        System.out.printf("%s; Spring %s; PathPatternParser; Java %s%n",
                ServerInfo.getServerInfo(), SpringVersion.getVersion(), System.getProperty("java.version"));
        tomcat.getServer().await();
    }

    @Configuration
    @EnableWebMvc
    public static class Mvc implements WebMvcConfigurer {
        @Override
        public void configurePathMatch(PathMatchConfigurer configurer) {
            var parser = new PathPatternParser();
            parser.setCaseSensitive(true);
            configurer.setPatternParser(parser);
        }

        @Bean
        public Routes routes() { return new Routes(); }
    }

    // Native mappings only. Policy assignment lives in the independent Rust harness.
    @RestController
    public static class Routes {
        private ResponseEntity<String> marker(String id) {
            return ResponseEntity.ok().header("X-Route-ID", id)
                    .header("Content-Type", "text/plain; charset=utf-8").body(id);
        }

        @GetMapping({"/admin", "/admin/", "/admin/**"})
        public ResponseEntity<String> admin() { return marker("admin"); }

        @GetMapping({"/files", "/files/", "/files/**"})
        public ResponseEntity<String> files() { return marker("files"); }

        @GetMapping({"/files/private", "/files/private/", "/files/private/**"})
        public ResponseEntity<String> privateFiles() { return marker("private"); }

        @PostMapping({"/files", "/files/", "/files/**"})
        public ResponseEntity<String> postFiles() { return marker("files"); }

        @GetMapping({"/exact.txt", "/exact.txt/"})
        public ResponseEntity<String> exact() { return marker("exact"); }

        @GetMapping({"/foo/{segment}/bar", "/foo/{segment}/bar/"})
        public ResponseEntity<String> parameterized() { return marker("parameterized"); }

        @RequestMapping("/**")
        public ResponseEntity<String> fallback() { return marker("public"); }
    }
}
