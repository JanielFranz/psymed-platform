package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetTaskByIdQuery;

import java.util.List;
import java.util.Optional;

/**
 * Service to handle queries related to tasks.
 * This service fetches task data based on various criteria.
 */
public interface TaskQueryService {

    /**
     * Handle the query to get all tasks.
     *
     * @param query the query object to fetch all tasks
     * @return a list of all tasks
     */
    List<Task> handle(GetAllTaskQuery query);

    /**
     * Handle the query to get a task by its ID.
     *
     * @param query the query object containing the task ID
     * @return an optional containing the task if found
     */
    Optional<Task> handle(GetTaskByIdQuery query);
}
