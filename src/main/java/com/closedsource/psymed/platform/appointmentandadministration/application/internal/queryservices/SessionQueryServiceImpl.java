package com.closedsource.psymed.platform.appointmentandadministration.application.internal.queryservices;

import com.closedsource.psymed.platform.appointmentandadministration.domain.model.aggregates.Session;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetAllSessionsByPatientIdQuery;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetAllSessionsByProfessionalIdQuery;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetSessionByIdQuery;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetSessionByPatientIdAndSessionIdQuery;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.valueobjects.PatientId;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.valueobjects.ProfessionalId;
import com.closedsource.psymed.platform.appointmentandadministration.domain.services.SessionQueryService;
import com.closedsource.psymed.platform.appointmentandadministration.infrastructure.persistence.jpa.repositories.SessionRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class SessionQueryServiceImpl implements SessionQueryService {

    private final SessionRepository sessionRepository;

    public SessionQueryServiceImpl(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    @Override
    public List<Session> handle(GetAllSessionsByPatientIdQuery query) {

        Long patientIdAsLong = Long.parseLong(query.patientId()); // Convert String to Long

        return sessionRepository.findAllByPatientId(new PatientId(patientIdAsLong));
    }

    @Override
    public List<Session> handle(GetAllSessionsByProfessionalIdQuery query) {

        Long professionalIdAsLong = Long.parseLong(query.professionalId()); // Convert String to Long
        return sessionRepository.findAllByProfessionalId(new ProfessionalId(professionalIdAsLong));
    }

    @Override
    public Optional<Session> handle(GetSessionByPatientIdAndSessionIdQuery query) {
        Long patientIdAsLong = Long.parseLong(query.patientId()); // Convert String to Long
        return sessionRepository.findByPatientIdAndId(new PatientId(patientIdAsLong), query.id());
    }

    @Override
    public Optional<Session> handle(GetSessionByIdQuery query) {
        return sessionRepository.findById(query.id());
    }

    @Override
    public List<Session> handle() {
        return sessionRepository.findAll();
    }
}
