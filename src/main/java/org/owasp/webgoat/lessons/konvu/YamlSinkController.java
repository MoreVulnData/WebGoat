package org.owasp.webgoat.lessons.konvu;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;

/**
 * Konvu test sink. Reachable CVE-2022-1471: SnakeYAML's {@link Yaml#load}
 * (default constructor, no SafeConstructor) instantiates arbitrary Java types
 * named in attacker-controlled YAML, yielding remote code execution.
 */
@RestController
public class YamlSinkController {

  @PostMapping("/konvu/yaml")
  public String run(@RequestBody String yaml) {
    Object loaded = new Yaml().load(yaml);
    return "loaded: " + loaded;
  }
}
