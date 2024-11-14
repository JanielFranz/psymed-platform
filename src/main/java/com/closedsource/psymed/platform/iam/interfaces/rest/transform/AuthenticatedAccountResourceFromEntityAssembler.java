package com.closedsource.psymed.platform.iam.interfaces.rest.transform;

import com.closedsource.psymed.platform.iam.domain.model.aggregate.Account;
import com.closedsource.psymed.platform.iam.interfaces.rest.resources.AuthenticatedAccountResource;

public class AuthenticatedAccountResourceFromEntityAssembler {
    //TODO: Implement token in the future
    public static AuthenticatedAccountResource toResourceFromEntity(Account entity, String token) {
        return new AuthenticatedAccountResource(entity.getId(), entity.getUserName(), token);
    }
}
