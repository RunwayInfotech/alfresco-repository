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

import java.security.PublicKey;

import javax.servlet.http.HttpServletRequest;

import org.alfresco.deployment.auth.DBPClaims;
import org.alfresco.deployment.auth.JWTUtils;
import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.repo.security.authentication.AuthenticationUtil.RunAsWork;
import org.alfresco.repo.security.authentication.external.RemoteUserMapper;
import org.alfresco.service.cmr.security.PersonService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A {@link RemoteUserMapper} implementation that detects and validates JWTs.
 * 
 * @author Gavin Cornwell
 */
public class TokenRemoteUserMapper implements RemoteUserMapper, ActivateableBean
{
    private static Log logger = LogFactory.getLog(TokenRemoteUserMapper.class);
    private static final String BEARER_PREFIX = "Bearer";
    
    /** Is the mapper enabled */
    private boolean isEnabled;
    
    /** Name of the header where the JWT is passed */
    private String header;
    
    /** Name of the claim in the JWT that holds the username */
    private String userNameClaim;
    
    /** The public key used for JWT validation */
    private String publicKey;

    /** The person service. */
    private PersonService personService;

    public void setActive(boolean isEnabled)
    {
        this.isEnabled = isEnabled;
    }
    
    public void setHeader(String header)
    {
        this.header = header;
    }

    public void setUserNameClaim(String userNameClaim)
    {
        this.userNameClaim = userNameClaim;
    }

    public void setPublicKey(String publicKey)
    {
        this.publicKey = publicKey;
    }

    /**
     * Sets the person service.
     * 
     * @param personService
     *            the person service
     */
    public void setPersonService(PersonService personService)
    {
        this.personService = personService;
    }

    /*
     * (non-Javadoc)
     * @see org.alfresco.web.app.servlet.RemoteUserMapper#getRemoteUser(javax.servlet.http.HttpServletRequest)
     */
    public String getRemoteUser(HttpServletRequest request)
    {
        if (logger.isDebugEnabled())
            logger.debug("Getting RemoteUser from token in http request.");
        
        if (!this.isEnabled)
        {
            if (logger.isDebugEnabled())
                logger.debug("DefaultRemoteUserMapper is disabled, returning null.");
            
            return null;
        }
        
        String headerUserId = extractUserFromHeader(request);
        
        if (logger.isDebugEnabled())
            logger.debug("The header user id is: " + headerUserId);
        
        if (headerUserId != null)
        {
            // Normalize the user ID taking into account case sensitivity settings
            String normalizedUserId =  normalizeUserId(headerUserId);
            
            if (logger.isDebugEnabled())
                logger.debug("Returning " + normalizedUserId);
            
            return normalizedUserId;
        }
        
        return null;
    }

    /**
     * Extracts the user name from the JWT in the configured header in the given request.
     * 
     * @param request The request containing the JWT
     * @return The user name or null if it can not be determined
     */
    private String extractUserFromHeader(HttpServletRequest request)
    {
        String userName = null;
        
        if (logger.isDebugEnabled())
            logger.debug("Retrieving JWT from header: " + this.header);
        
        String headerString = request.getHeader(this.header);
        
        if (logger.isDebugEnabled())
            logger.debug("Retrieved header: " + headerString);
        
        if (headerString != null && !headerString.isEmpty() && headerString.startsWith(BEARER_PREFIX))
        {
            PublicKey keycloakPublicKey = null;
            DBPClaims claims = null;
            
            try
            {
                if (logger.isDebugEnabled())
                    logger.debug("Checking JWT with public key: " + this.publicKey);
                
                keycloakPublicKey = JWTUtils.generatePublicKey(this.publicKey);
                claims = JWTUtils.parseJwt(headerString, keycloakPublicKey);
            }
            catch (Exception e)
            {
                logger.error("Failed to extract token from header: ", e);
                return null;
            }
            
            if (logger.isDebugEnabled())
                logger.debug("Retrieving username from claim: " + this.userNameClaim);
            
            userName = (String)claims.get(this.userNameClaim);
            
            if (logger.isDebugEnabled())
                logger.debug("Retrieved username: " + userName);
        }
        
        return userName;
    }
    
    /**
     * Normalizes a user id, taking into account existing user accounts and case sensitivity settings.
     * 
     * @param userId
     *            the user id
     * @return the string
     */
    private String normalizeUserId(final String userId)
    {
        if (userId == null)
        {
            return null;
        }
        
        String normalized = AuthenticationUtil.runAs(new RunAsWork<String>()
        {
            public String doWork() throws Exception
            {
                return personService.getUserIdentifier(userId);
            }
        }, AuthenticationUtil.getSystemUserName());
        
        if (logger.isDebugEnabled())
            logger.debug("The normalized user name for '" + userId + "' is: " + normalized);
        
        return normalized == null ? userId : normalized;
    }

    /*
     * (non-Javadoc)
     * @see org.alfresco.repo.management.subsystems.ActivateableBean#isActive()
     */
    public boolean isActive()
    {
        return this.isEnabled;
    }
}
