package org.owasp.webgoat.lessons.konvu;

import java.sql.Connection;
import java.sql.DriverManager;
import org.h2.Driver;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Konvu test sink. Reachable CVE-2021-42392: an attacker-controlled H2 JDBC URL
 * (e.g. {@code jdbc:h2:mem:test;INIT=...} or a JNDI datasource) is passed to
 * {@link DriverManager#getConnection}, letting H2 execute arbitrary code.
 */
@RestController
public class H2SinkController {

  @PostMapping("/konvu/h2")
  public String run(@RequestBody String jdbcUrl) throws Exception {
    Driver.load(); // ensures the vulnerable org.h2 driver is registered
    try (Connection c = DriverManager.getConnection(jdbcUrl)) {
      return "connected: " + c.getMetaData().getDatabaseProductName();
    }
  }
}
