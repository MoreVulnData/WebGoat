package org.owasp.webgoat.lessons.konvu;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Konvu test sink. Reachable CVE-2015-7501: commons-collections4's
 * {@link InvokerTransformer} reflectively invokes an arbitrary method — the core
 * of the classic gadget-chain RCE. Here it invokes {@code Runtime.exec} on the
 * attacker-controlled command from the request body.
 */
@RestController
public class CommonsCollectionsSinkController {

  @PostMapping("/konvu/collections")
  @SuppressWarnings({"unchecked", "rawtypes"})
  public String run(@RequestBody String command) throws Exception {
    Transformer transformer =
        new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {command});
    Object process = transformer.transform(Runtime.getRuntime());
    return "executed: " + process;
  }
}
