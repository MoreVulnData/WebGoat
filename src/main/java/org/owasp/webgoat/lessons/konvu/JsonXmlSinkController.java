package org.owasp.webgoat.lessons.konvu;

import org.json.JSONObject;
import org.json.XML;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Konvu test sink. Reachable CVE-2022-45688: {@link XML#toJSONObject} on
 * attacker-controlled XML overflows the stack (unbounded nesting), a
 * denial-of-service in org.json.
 */
@RestController
public class JsonXmlSinkController {

  @PostMapping("/konvu/json")
  public String run(@RequestBody String xml) {
    JSONObject parsed = XML.toJSONObject(xml);
    return parsed.toString();
  }
}
