package com.madeeasy.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.util.Date;
import java.util.List;
import java.util.Set;

@Getter
@Setter
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "customer")
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false)
    private String name;
    @Column(nullable = false)
    private String email;
//    @Column(nullable = false)
//    @JsonIgnore
    private String password;

    /**
     * @ElementCollection is not only used in conjunction with @Enumerated(EnumType.STRING). The @ElementCollection
     * annotation is a general-purpose JPA annotation used to map a collection of basic types or embeddable objects.
     * It is commonly used with @Enumerated(EnumType.STRING) to map a collection of enumerated values as strings, but
     * it can also be used with other types
     */
    /**
     * In this example, the Customer entity class has a list of roles represented by the roles field.
     * The @ElementCollection annotation is used to indicate that this field represents a collection of elements
     * rather than a separate entity. In this case, it represents a collection of roles for a customer.
     * The @Enumerated(EnumType.STRING) annotation specifies that the values of
     * the roles field should be mapped to their string representations. The @CollectionTable annotation defines
     * the table to store the roles.
     */
    // this @ElementCollection is mandatory to specify that the field represents a collection of elements.
    @ElementCollection(targetClass = Roles.class, fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    /**
     * @CollectionTable: This annotation specifies the name of the table that will be used to store the collection of roles.
     * In this case, the table name is "customer_roles".
     *
     * joinColumns = @JoinColumn(name = "customer_id"): This annotation specifies the foreign key column that links the customer
     * entity to the roles table. It indicates that the "customer_id" column in the "customer_roles" table will be used to
     * reference the customer.
     */
    // this is used to customize the name of table ane column so @CollectionTable is optional
//    @CollectionTable(name = "customer_roles", joinColumns = @JoinColumn(name = "customer_id"))
    private Set<Roles> roles;

    @CreationTimestamp
    @Temporal(TemporalType.TIMESTAMP)
    @Column(updatable = false)
    private Date createdAt;

    @UpdateTimestamp
    @Temporal(TemporalType.TIMESTAMP)
    private Date updatedAt;

}
