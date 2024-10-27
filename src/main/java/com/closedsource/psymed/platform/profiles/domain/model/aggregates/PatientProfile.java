package com.closedsource.psymed.platform.profiles.domain.model.aggregates;

import com.closedsource.psymed.platform.profiles.domain.model.commands.CreatePatientProfileCommand;
import com.closedsource.psymed.platform.profiles.domain.model.valueobjects.Email;
import com.closedsource.psymed.platform.profiles.domain.model.valueobjects.PersonName;
import com.closedsource.psymed.platform.profiles.domain.model.valueobjects.StreetAddress;
import com.closedsource.psymed.platform.shared.domain.model.aggregates.AuditableAbstractAggregateRoot;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.AbstractAggregateRoot;

@NoArgsConstructor
@Entity
public class PatientProfile extends AuditableAbstractAggregateRoot<PatientProfile> {


    @Embedded
    private PersonName personName;

    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "street", column = @Column(name = "address_street")),
            @AttributeOverride(name = "city", column = @Column(name = "address__city")),
            @AttributeOverride(name = "country", column = @Column(name = "address_country"))
    })
    private StreetAddress streetAddress;

    @Embedded
    private Email email;

    public PatientProfile(String firstName, String lastName, String street, String city, String country, String email){
        this.personName = new PersonName(firstName, lastName);
        this.streetAddress = new StreetAddress(street, city, country);
        this.email = new Email(email);
    }

    public PatientProfile(CreatePatientProfileCommand command) {
        this.personName = new PersonName(command.firstName(), command.lastName());
        this.email = new Email(command.email());
        this.streetAddress = new StreetAddress(command.street(), command.city(), command.country());
    }

    public void updateEmail(String email) {
        this.email = new Email(email);
    }

    public void updateName(String firstName, String lastName) {
        this.personName = new PersonName(firstName, lastName);
    }

    public void updateAddress(String street, String city, String country) {
        this.streetAddress = new StreetAddress(street, city, country);
    }

    public String getFullName() {
        return personName.getFullName();
    }

    public String getStreetAddress() {
        return streetAddress.getStreetAddress();
    }

    public String getEmail() {
        return email.email();
    }





}
