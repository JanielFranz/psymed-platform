package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllTreatmentTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetTreatmentTaskByIdQuery;

import java.util.List;
import java.util.Optional;

/**
 * Service to handle queries related to treatment tasks.
 * This service fetches treatment task data based on various criteria.
 */
public interface TreatmentTaskQueryService {

    /**
     * Handle the query to get all treatment tasks.
     *
     * @param query the query object to fetch all treatment tasks
     * @return a list of all treatment tasks
     */
    List<TreatmentTask> handle(GetAllTreatmentTaskQuery query);

    /**
     * Handle the query to get a treatment task by its ID.
     *
     * @param query the query object containing the treatment task ID
     * @return an optional containing the treatment task if found
     */
    Optional<TreatmentTask> handle(GetTreatmentTaskByIdQuery query);
}
