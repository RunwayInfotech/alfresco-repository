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
import java.util.Calendar;

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
    private static final String TEST_INCORRECT_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi6anG3lANB" +
                "/Cgn+tIB7CL1zEU+ckHl1xJEVstVVP0GoGeTP+CYS1S7cFGW/46gN68UKrWCBzko" +
                "EYgJ5Z0cTuvTFdhSaJSKQ6bD+/qbbF5BsPp0dRatlD3Z90cYe2hABFbD9MMP7yMP" +
                "2z3tzdS0GTUNUzyYf4qEHtk3ncomHRjVqPO9CwvIfimCwERSM9Gt/6Oa1IiRk5Ma" + 
                "k/BbMV+OkqnoIjgRpI4xiCxoMyNRQOkr253LULBzbDbfSThsMy8hnEIvkAzRqVIz" + 
                "Rw9z9qh02z5Am7t06P7Rq+WLdTfpDgLXexjH71AKDzJYlCQ4R8lM55XdLKyzW/un" + 
                "HFdqXc7tO5LQIDAQAB";
    
    private static final String CONFIG_PUBLIC_KEY = "token.authentication.publicKey";
    private static final String CONFIG_HEADER = "token.authentication.header";
    private static final String CONFIG_USERNAME_CLAIM = "token.authentication.userName.claim";
    
    private static final String TEST_USER_USERNAME = "testuser";
    private static final String TEST_USER_EMAIL = "testuser@mail.com";
    
    private static final String DEFAULT_HEADER = "Authorization";
    private static final String CUSTOM_HEADER = "X-Alfresco-Token-Test";
    private static final String CUSTOM_USERNAME_CLAIM = "custom:attribute";
    
    private static final String BEARER_PREFIX = "Bearer ";
    
    ApplicationContext ctx = ApplicationContextHelper.getApplicationContext();
    DefaultChildApplicationContextManager childApplicationContextManager;
    ChildApplicationContextFactory childApplicationContextFactory;
    
    private Key testJwtSigningKey;

    /* (non-Javadoc)
     * @see junit.framework.TestCase#setUp()
     */
    @Override
    protected void setUp() throws Exception
    {
        // switch authentication to use token auth
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
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_PUBLIC_KEY);
        
        // create token
        String jwt = generateToken(false);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(DEFAULT_HEADER)).thenReturn(BEARER_PREFIX + jwt);
        
        // validate correct user was found
        assertEquals(TEST_USER_USERNAME, ((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    public void testNonDefaultHeader() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_PUBLIC_KEY);
        childApplicationContextFactory.setProperty(CONFIG_HEADER, CUSTOM_HEADER);
        
        // create token
        String jwt = generateToken(false);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(CUSTOM_HEADER)).thenReturn(BEARER_PREFIX + jwt);
        
        // validate correct user was found
        assertEquals(TEST_USER_USERNAME, ((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    public void testNonDefaultUsernameClaim() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_PUBLIC_KEY);
        childApplicationContextFactory.setProperty(CONFIG_USERNAME_CLAIM, CUSTOM_USERNAME_CLAIM);
        
        // create token
        String jwt = generateToken(false);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(DEFAULT_HEADER)).thenReturn(BEARER_PREFIX + jwt);
        
        // validate correct user was found
        assertEquals(TEST_USER_USERNAME, ((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    public void testWrongPublicKey() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_INCORRECT_PUBLIC_KEY);
        
        // create token
        String jwt = generateToken(false);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(DEFAULT_HEADER)).thenReturn(BEARER_PREFIX + jwt);
        
        // ensure null is returned if the public key is wrong
        assertNull(((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    public void testInvalidJwt() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_PUBLIC_KEY);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(DEFAULT_HEADER)).thenReturn(BEARER_PREFIX + "thisisnotaJWT");
        
        // ensure null is returned if the JWT is invalid
        assertNull(((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    public void testExpiredToken() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_PUBLIC_KEY);
        
        // create token
        String jwt = generateToken(true);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(DEFAULT_HEADER)).thenReturn(BEARER_PREFIX + jwt);
        
        // ensure null is returned if the token has expired
        assertNull(((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    public void testMissingHeader() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_PUBLIC_KEY);
        childApplicationContextFactory.setProperty(CONFIG_HEADER, "Invalid-Header");
        
        // create token
        String jwt = generateToken(true);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(DEFAULT_HEADER)).thenReturn(BEARER_PREFIX + jwt);
        
        // ensure null is returned if the header was configured incorrectly
        assertNull(((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    public void testMissingUsernameClaim() throws Exception
    {
        // set the public key property
        childApplicationContextFactory.stop();
        childApplicationContextFactory.setProperty(CONFIG_PUBLIC_KEY, TEST_PUBLIC_KEY);
        childApplicationContextFactory.setProperty(CONFIG_USERNAME_CLAIM, "InvalidClaim");
        
        // create token
        String jwt = generateToken(true);
        
        // Mock a request with the JWT in the header
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getHeader(DEFAULT_HEADER)).thenReturn(BEARER_PREFIX + jwt);
        
        // ensure null is returned if the header was configured incorrectly
        assertNull(((RemoteUserMapper) childApplicationContextFactory.getApplicationContext().getBean(
              "remoteUserMapper")).getRemoteUser(mockRequest));
    }
    
    
    /**
     * Utility method to create tokens for testing
     * 
     * @param expired Determines whether to create an expired JWT
     * @return The string representation of the JWT
     */
    private String generateToken(boolean expired) throws Exception
    {
        DBPClaims testClaims = new DBPClaims();
        
        // setup standard attributes
        testClaims.setClientId("test-client")
            .setUsername(TEST_USER_USERNAME)
            .setEmail(TEST_USER_EMAIL)
            .setLastname("Bloggs")
            .setName("Joe");
        
        // add preferred_username claim
        testClaims.put("preferred_username", TEST_USER_USERNAME);
        
        // add a custom claim
        testClaims.put(CUSTOM_USERNAME_CLAIM, TEST_USER_USERNAME);
        
        if (expired)
        {
            Calendar expiration = Calendar.getInstance();
            expiration.add(Calendar.SECOND, -60);
            testClaims.setExpiration(expiration.getTime());
        }
        
        // build and return JWT
        return JWTUtils.buildJwt(testClaims, this.testJwtSigningKey);
    }
}
