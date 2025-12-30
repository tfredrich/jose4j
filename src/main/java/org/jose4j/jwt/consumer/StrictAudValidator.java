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

import java.util.Collections;
import java.util.Set;

/**
 * Validate the "aud" (Audience) Claim per https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/
 * This validator is strict and only allows a single audience value.
 */
public final class StrictAudValidator extends AudValidator
{
    private final Set<String> acceptableAudiences;
    private final boolean requireAudience;

    public StrictAudValidator(Set<String> acceptableAudiences, boolean requireAudience)
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

        Object audienceObject = jwtClaims.getRawAudience();
        if (!(audienceObject instanceof String))
        {
            return new Error(ErrorCodes.AUDIENCE_INVALID, "audience claim is not a string");
        }

        String audience = (String) audienceObject;

        if (!acceptableAudiences.contains(audience))
        {
            return getAudValidatorError(Collections.singletonList(audience), acceptableAudiences);
        }

        return null;
    }
}
