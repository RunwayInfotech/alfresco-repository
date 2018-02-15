/*
 * #%L
 * Alfresco Repository
 * %%
 * Copyright (C) 2005 - 2018 Alfresco Software Limited
 * %%
 * This file is part of the Alfresco software. 
 * If the software was purchased under a paid Alfresco license, the terms of 
 * the paid license agreement will prevail.  Otherwise, the software is 
 * provided under the following open source license terms:
 * 
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */
package org.alfresco.repo.security.authentication.token;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;

import javax.servlet.http.HttpServletRequest;

import org.alfresco.deployment.auth.DBPClaims;
import org.alfresco.deployment.auth.JWTUtils;
import org.alfresco.repo.management.subsystems.AbstractChainedSubsystemTest;
import org.alfresco.repo.management.subsystems.ChildApplicationContextFactory;
import org.alfresco.repo.management.subsystems.DefaultChildApplicationContextManager;
import org.alfresco.repo.security.authentication.external.RemoteUserMapper;
import org.alfresco.util.ApplicationContextHelper;
import org.springframework.context.ApplicationContext;


/**
 * Tests the token based authentication subsystem.
 * 
 * @author Gavin Cornwell
 *
 */
public class TokenRemoteUserMapperTest extends AbstractChainedSubsystemTest
{
    private static final String TEST_KEYSTORE_PATH = "/alfresco/subsystems/tokenAuthentication/keystore.jks";
    private static final String TEST_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWLQxipXNe6cLnVPGy7l" + 
                "BgyR51bDiK7Jso8Rmh2TB+bmO4fNaMY1ETsxECSM0f6NTV0QHks9+gBe+pB6JNeM" + 
                "uPmaE/M/MsE9KUif9L2ChFq3zor6s2foFv2DTiTkij+1aQF9fuIjDNH4FC6L252W" + 
                "ydZzh+f73Xuy5evdPj+wrPYqWyP7sKd+4Q9EIILWAuTDvKEjwyZmIyfM/nUn6ltD" + 
                "P6W8xMP0PoEJNAAp79anz2jk2HP2PvC2qdjVsphdTk3JG5qQMB0WJUh4Kjgabd4j" + 
                "QJ77U8gTRswKgNHRRPWhruiIcmmkP+zI0ozNW6rxH3PF4L7M9rXmfcmUcBcKf+Yx" + 
                "jwIDAQAB";
    
    ApplicationContext ctx = ApplicationContextHelper.getApplicationContext();
    DefaultChildApplicationContextManager childApplicationContextManager;
    ChildApplicationContextFactory childApplicationContextFactory;
    
    private Key testJwtSigningKey;
//    private PublicKey testJwtPublicKey;

    /* (non-Javadoc)
     * @see junit.framework.TestCase#setUp()
     */
    @Override
    protected void setUp() throws Exception
    {
        childApplicationContextManager = (DefaultChildApplicationContextManager) ctx.getBean("Authentication");
        childApplicationContextManager.stop();
        childApplicationContextManager.setProperty("chain", "token1:token");
        childApplicationContextFactory = getChildApplicationContextFactory(childApplicationContextManager, "token1");
        childApplicationContextFactory.setProperty("token.authentication.enabled", "true");
        
        // extract signing key
        InputStream keyStoreInputStream = TokenRemoteUserMapperTest.class.getResourceAsStream(TEST_KEYSTORE_PATH);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(keyStoreInputStream, "password".toCharArray());
        this.testJwtSigningKey = keystore.getKey("changeme-dbp", "password".toCharArray());
        
        // extract public key
//        this.testJwtPublicKey = JWTUtils.generatePublicKey(TEST_PUBLIC_KEY);
    }
    
    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    @Override
    protected void tearDown() throws Exception
    {
        childApplicationContextManager.destroy();
        childApplicationContextManager = null;
        childApplicationContextFactory = null;
    }

    public void testValidToken() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty("token.authentication.publicKey", TEST_PUBLIC_KEY);
        
        // create token
        String jwt = generateToken();
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader("Authorization")).thenReturn("Bearer " + jwt);
        
        // validate correct user was found
        assertEquals("testuser", ((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    private String generateToken() throws Exception
    {
        DBPClaims testClaims = new DBPClaims();
        
        // setup standard attributes
        testClaims.setClientId("test-client")
            .setUsername("testuser")
            .setEmail("testuser@mail.com")
            .setLastname("Bloggs")
            .setName("Joe");
        
        // add preferred_username
        testClaims.put("preferred_username", "testuser");
        
        // build and return JWT
        return JWTUtils.buildJwt(testClaims, this.testJwtSigningKey);
    }
}
