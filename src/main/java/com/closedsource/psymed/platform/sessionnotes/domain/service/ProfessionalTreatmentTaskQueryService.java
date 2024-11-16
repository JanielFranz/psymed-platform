package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.ProfessionalTreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllProfessionalTreatmentTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetProfessionalTreatmentTaskByIdQuery;

import java.util.List;
import java.util.Optional;

/**
 * Service to handle queries related to professional treatment tasks.
 * This service fetches data for professional treatment tasks based on various criteria.
 */
public interface ProfessionalTreatmentTaskQueryService {

    /**
     * Handle the query to get all professional treatment tasks.
     *
     * @param query the query object to fetch all professional treatment tasks
     * @return a list of all professional treatment tasks
     */
    List<ProfessionalTreatmentTask> handle(GetAllProfessionalTreatmentTaskQuery query);

    /**
     * Handle the query to get a professional treatment task by its ID.
     *
     * @param query the query object containing the professional treatment task ID
     * @return an optional containing the professional treatment task if found
     */
    Optional<ProfessionalTreatmentTask> handle(GetProfessionalTreatmentTaskByIdQuery query);
}
