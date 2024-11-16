package com.closedsource.psymed.platform.appointmentandadministration.domain.model.aggregates;

import com.closedsource.psymed.platform.appointmentandadministration.domain.model.commands.CreateSessionCommand;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.valueobjects.AppointmentDate;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.valueobjects.PatientId;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.valueobjects.ProfessionalId;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.valueobjects.SessionTime;
import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.domain.AbstractAggregateRoot;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * Session aggregate that represents a session between a patient and a professional.
 * This class encapsulates the main logic related to managing a session.
 */
@Entity
@EntityListeners(AuditingEntityListener.class)
public class Session extends AbstractAggregateRoot<Session> {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Getter
    @Id
    private Long id;

    @Embedded
    @Getter
    private PatientId patientId;

    @Embedded
    @Getter
    private ProfessionalId professionalId;

    @Embedded
    @Getter
    private AppointmentDate appointmentDate;

    @Embedded
    @Getter
    private SessionTime sessionTime;

    @ManyToOne
    @JoinColumn(name = "notes")
    @Getter
    @Setter
    private Note note;

    @Column(nullable = false, updatable = false)
    @CreatedDate
    private Date createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private Date updatedAt;

    protected Session() {}

    /**
     * Creates a new session from a CreateSessionCommand.
     *
     * @param command The command object containing all the necessary details to create a session.
     */
    public Session(CreateSessionCommand command) {
        // You should now directly use the patientId and professionalId from the command, no need to wrap them again
        this.patientId = new PatientId(command.patientId());
        this.professionalId = new ProfessionalId(command.professionalId());
        this.appointmentDate = new AppointmentDate(command.appointmentDate());
        this.sessionTime = new SessionTime(command.sessionTime());
    }


}