/*
 * Copyright 2012-2017 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import java.util.List;
import java.util.Set;

/**
 * Validate the "aud" (Audience) Claim per http://tools.ietf.org/html/rfc7519#section-4.1.3
 */
public final class GeneralAudValidator extends AudValidator
{
    private final Set<String> acceptableAudiences;
    private final boolean requireAudience;

    public GeneralAudValidator(Set<String> acceptableAudiences, boolean requireAudience)
    {
        this.acceptableAudiences = acceptableAudiences;
        this.requireAudience = requireAudience;
    }

    @Override
    public Error validate(JwtContext jwtContext) throws MalformedClaimException
    {
        final JwtClaims jwtClaims = jwtContext.getJwtClaims();

        if (!jwtClaims.hasAudience())
        {
            return requireAudience ? MISSING_AUD : null;
        }

        List<String> audiences = jwtClaims.getAudience();

        boolean ok = false;
        for (String audience : audiences)
        {
            if (acceptableAudiences.contains(audience))
            {
                ok = true;
            }
        }

        if (!ok)
        {
            return getAudValidatorError(audiences, acceptableAudiences);
        }

        return null;
    }

}
