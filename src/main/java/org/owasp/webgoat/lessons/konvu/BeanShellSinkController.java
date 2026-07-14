package org.owasp.webgoat.lessons.konvu;

import bsh.Interpreter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Konvu test sink. Reachable CVE-2016-2510: BeanShell's {@link Interpreter#eval}
 * executes an attacker-controlled script from the request body, yielding remote
 * code execution (e.g. {@code Runtime.getRuntime().exec(...)}).
 */
@RestController
public class BeanShellSinkController {

  @PostMapping("/konvu/bsh")
  public String run(@RequestBody String script) throws Exception {
    Object result = new Interpreter().eval(script);
    return "eval: " + result;
  }
}
