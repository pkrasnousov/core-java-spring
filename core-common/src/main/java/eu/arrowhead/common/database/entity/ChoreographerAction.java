package eu.arrowhead.common.database.entity;

import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import eu.arrowhead.common.CoreDefaults;

@Entity
@Table(uniqueConstraints = @UniqueConstraint(columnNames = {"name", "planId"}))
public class ChoreographerAction {
	
	//=================================================================================================
	// members

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(length = CoreDefaults.VARCHAR_BASIC, nullable = false)
    private String name;

    // The plan whose first action is this action must be mapped like this. Better name needed.
    @OneToOne(mappedBy = "firstAction", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private ChoreographerPlan planFirstAction;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "planId", referencedColumnName = "id", nullable = false)
    private ChoreographerPlan plan;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "nextActionId", referencedColumnName = "id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private ChoreographerAction nextAction;

    @OneToMany(mappedBy = "actionFirstStep", fetch = FetchType.LAZY, orphanRemoval = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Set<ChoreographerStep> firstStepEntries = new HashSet<>();

    @OneToMany(mappedBy = "action", fetch = FetchType.LAZY, orphanRemoval = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Set<ChoreographerStep> stepEntries = new HashSet<>();

    @Column(nullable = false, updatable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private ZonedDateTime createdAt;

    @Column(nullable = false, updatable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")
    private ZonedDateTime updatedAt;

    //=================================================================================================
	// methods

    //-------------------------------------------------------------------------------------------------
    public ChoreographerAction() {}

    //-------------------------------------------------------------------------------------------------
	public ChoreographerAction(final String name, final ChoreographerAction nextAction) {
        this.name = name;
        this.nextAction = nextAction;
    }

    //-------------------------------------------------------------------------------------------------

    public long getId() { return id; }
    public String getName() { return name; }
    public ChoreographerPlan getPlanFirstAction() { return planFirstAction; }
    public ChoreographerPlan getPlan() { return plan; }
    public ChoreographerAction getNextAction() { return nextAction; }
    public Set<ChoreographerStep> getFirstStepEntries() { return firstStepEntries; }
    public Set<ChoreographerStep> getStepEntries() { return stepEntries; }
    public ZonedDateTime getCreatedAt() { return createdAt; }
    public ZonedDateTime getUpdatedAt() { return updatedAt; }

    //-------------------------------------------------------------------------------------------------

    public void setId(long id) { this.id = id; }
    public void setName(String name) { this.name = name; }
    public void setPlanFirstAction(ChoreographerPlan planFirstAction) { this.planFirstAction = planFirstAction; }
    public void setPlan(ChoreographerPlan plan) { this.plan = plan; }
    public void setNextAction(ChoreographerAction nextAction) { this.nextAction = nextAction; }
    public void setFirstStepEntries(Set<ChoreographerStep> firstStepEntries) { this.firstStepEntries = firstStepEntries; }
    public void setStepEntries(Set<ChoreographerStep> stepEntries) { this.stepEntries = stepEntries; }
    public void setCreatedAt(ZonedDateTime createdAt) { this.createdAt = createdAt; }
    public void setUpdatedAt(ZonedDateTime updatedAt) { this.updatedAt = updatedAt; }

    //-------------------------------------------------------------------------------------------------
	@PrePersist
    public void onCreate() {
        this.createdAt = ZonedDateTime.now();
        this.updatedAt = this.createdAt;
    }

    //-------------------------------------------------------------------------------------------------
	@PreUpdate
    public void onUpdate() {
        this.updatedAt = ZonedDateTime.now();
    }
}