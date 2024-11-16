package com.closedsource.psymed.platform.medication.application.internal.querieservices;

import com.closedsource.psymed.platform.medication.domain.model.aggregates.Pills;
import com.closedsource.psymed.platform.medication.domain.model.queries.GetAllPillsQuery;
import com.closedsource.psymed.platform.medication.domain.model.queries.GetPillsByIdQuery;
import com.closedsource.psymed.platform.medication.domain.model.queries.GetPillByNameQuery;
import com.closedsource.psymed.platform.medication.domain.services.PillQueryService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PillQueryServiceImpl implements PillQueryService {
    @Override
    public Optional<Pills> handle(GetPillByNameQuery query) {
        return Optional.empty();
    }

    @Override
    public List<Pills> handle(GetAllPillsQuery query) {
        return List.of();
    }

    @Override
    public Optional<Pills> handle(GetPillsByIdQuery getPillsByIdQuery) {
        return Optional.empty();
    }
}
