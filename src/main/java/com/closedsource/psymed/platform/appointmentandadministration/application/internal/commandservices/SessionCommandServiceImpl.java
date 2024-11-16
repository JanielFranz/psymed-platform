package com.closedsource.psymed.platform.appointmentandadministration.application.internal.commandservices;

import com.closedsource.psymed.platform.appointmentandadministration.application.internal.outboundservices.AppointmentVersionOfExternalProfileService;
import com.closedsource.psymed.platform.appointmentandadministration.application.internal.outboundservices.acl.AppointmentVersionOfExternalProfileServiceImpl;
import com.closedsource.psymed.platform.appointmentandadministration.domain.exceptions.PatientNotFoundException;
import com.closedsource.psymed.platform.appointmentandadministration.domain.exceptions.ProfessionalNotFoundException;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.aggregates.Session;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.commands.CreateSessionCommand;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.commands.UpdateSessionNoteCommand;
import com.closedsource.psymed.platform.appointmentandadministration.domain.services.SessionCommandService;
import com.closedsource.psymed.platform.appointmentandadministration.infrastructure.persistence.jpa.repositories.SessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class SessionCommandServiceImpl implements SessionCommandService {
    private final SessionRepository sessionRepository;
    private final AppointmentVersionOfExternalProfileService externalProfileService; // Service to check patient and professional existence

    public SessionCommandServiceImpl(SessionRepository sessionRepository, AppointmentVersionOfExternalProfileServiceImpl externalProfileService) {
        this.sessionRepository = sessionRepository;
        this.externalProfileService = externalProfileService;
    }

    /** {@inheritDoc} */
    @Override
    @Transactional
    public Optional<Session> handle(CreateSessionCommand command) {
        // Check if the patient and professional exist
        boolean patientExists = externalProfileService.existsPatientById(command.patientId());
        boolean professionalExists = externalProfileService.existsProfessionalById(command.professionalId());

        if (!patientExists) {
            throw new PatientNotFoundException(command.patientId()); // Custom exception for patient not found
        }
        if (!professionalExists) {
            throw new ProfessionalNotFoundException(command.professionalId()); // Custom exception for professional not found
        }

        // Create a new session based on the command
        var session = new Session(command);
        var createdSession = sessionRepository.save(session);
        return Optional.of(createdSession);
    }

    @Override
    public Optional<Session> handle(UpdateSessionNoteCommand command) {

        var session = sessionRepository.findById(command.id()).get();
        session.setNote(command.note());

        var optionalSession = sessionRepository.save(session);

        return Optional.of(optionalSession);
    }

}
