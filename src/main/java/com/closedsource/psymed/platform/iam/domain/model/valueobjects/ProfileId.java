package com.closedsource.psymed.platform.iam.domain.model.valueobjects;

import jakarta.persistence.Embeddable;

@Embeddable
public record ProfileId(Long profileId) {
    public ProfileId {
        if (profileId == null) {
            throw new IllegalArgumentException("id cannot be null");
        }
    }
}
