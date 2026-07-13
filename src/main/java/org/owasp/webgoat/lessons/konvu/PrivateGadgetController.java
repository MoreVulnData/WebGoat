/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.konvu;

import com.konvutest.Gadget;
import java.util.Base64;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Konvu test endpoint. An HTTP entry point that deserializes untrusted request
 * bytes through the private {@code com.konvutest:private-lib} gadget. Because
 * commons-collections 3.2.1 (a transitive of private-lib, resolvable only via
 * the private registry) is on the classpath, this is a reachable CVE-2015-6420
 * sink — a crafted gadget chain in the payload achieves remote code execution.
 */
@RestController
public class PrivateGadgetController {

  @PostMapping("/private-gadget")
  public String run(@RequestBody String base64Payload) throws Exception {
    byte[] data = Base64.getDecoder().decode(base64Payload);
    Object result = Gadget.deserialize(data);
    return "deserialized: " + result;
  }
}
