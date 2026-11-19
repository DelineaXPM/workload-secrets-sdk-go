package workloadsecrets

import (
	"testing"

	"github.com/google/uuid"
	serialization "github.com/microsoft/kiota-abstractions-go/serialization"
	jsonserialization "github.com/microsoft/kiota-serialization-json-go"

	models "github.com/DelineaXPM/workload-secrets-sdk-go/generated/models"
)

func str(value string) *string { return &value }

func write(t *testing.T, value serialization.Parsable) []byte {
	t.Helper()
	writer := jsonserialization.NewJsonSerializationWriter()
	if err := writer.WriteObjectValue("", value); err != nil {
		t.Fatal(err)
	}
	content, err := writer.GetSerializedContent()
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func read(t *testing.T, content []byte, factory serialization.ParsableFactory) serialization.Parsable {
	t.Helper()
	node, err := jsonserialization.NewJsonParseNodeFactory().GetRootParseNode("application/json", content)
	if err != nil {
		t.Fatal(err)
	}
	value, err := node.GetObjectValue(factory)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// A caller sets type by hand, assigns access through the generated wrapper, and reads a body back through the discriminator.
func TestDatabaseDynamicSecretWithALevelRoundTripsThroughTheAccessWrapper(t *testing.T) {
	level := models.READ_DYNAMICSECRETACCESSLEVEL
	levelAccess := models.NewLevelAccess()
	levelAccess.SetLevel(&level)
	body := models.NewDatabaseDynamicSecret()
	body.SetBaseSecretPath(str("infra/mysql-prod"))
	body.SetAccess(levelAccess)

	read := read(t, write(t, body), models.CreateDynamicSecretDefinitionFromDiscriminatorValue)

	database, ok := read.(models.DatabaseDynamicSecretable)
	if !ok {
		t.Fatalf("read back %T, want a database dynamic secret", read)
	}
	if got, ok := database.GetAccess().(models.LevelAccessable); !ok || *got.GetLevel() != level {
		t.Error("the level was lost")
	}
}

func TestDatabaseDynamicSecretWithGrantsRoundTrips(t *testing.T) {
	scope := models.NewGrantScope()
	scope.SetDatabase(str("orders"))
	grant := models.NewGrant()
	grant.SetPrivileges([]models.GrantPrivilege{models.SELECT_GRANTPRIVILEGE, models.INSERT_GRANTPRIVILEGE})
	grant.SetOn(scope)
	grants := models.NewGrantsAccess()
	grants.SetGrants([]models.Grantable{grant})
	body := models.NewDatabaseDynamicSecret()
	body.SetBaseSecretPath(str("infra/postgres-prod"))
	body.SetAccess(grants)

	database := read(t, write(t, body), models.CreateDynamicSecretDefinitionFromDiscriminatorValue).(models.DatabaseDynamicSecretable)

	got := database.GetAccess().(models.GrantsAccessable).GetGrants()
	if len(got) != 1 || len(got[0].GetPrivileges()) != 2 || *got[0].GetOn().GetDatabase() != "orders" {
		t.Errorf("grants were not preserved: %v", got)
	}
}

func TestTheTwoAzureDynamicSecretCasesRoundTripAsTheirOwnType(t *testing.T) {
	ephemeral := models.NewAzureEphemeralDynamicSecret()
	ephemeral.SetBaseSecretPath(str("infra/azure"))
	ephemeral.SetScope(str("/subscriptions/11111111-1111-1111-1111-111111111111"))
	role := uuid.New()
	ephemeral.SetRoleDefinitionId(&role)
	existing := models.NewAzureExistingAppDynamicSecret()
	existing.SetBaseSecretPath(str("infra/azure"))
	app := uuid.New()
	existing.SetAppObjectId(&app)

	if _, ok := read(t, write(t, ephemeral), models.CreateDynamicSecretDefinitionFromDiscriminatorValue).(models.AzureEphemeralDynamicSecretable); !ok {
		t.Error("azureEphemeral did not read back as its own type")
	}
	if _, ok := read(t, write(t, existing), models.CreateDynamicSecretDefinitionFromDiscriminatorValue).(models.AzureExistingAppDynamicSecretable); !ok {
		t.Error("azureExistingApp did not read back as its own type")
	}
}

func credential() models.UsernamePasswordCredentialable {
	value := models.NewUsernamePasswordCredential()
	value.SetUsername(str("admin"))
	value.SetPassword(str("pw"))
	return value
}

func TestBaseSecretCasesRoundTrip(t *testing.T) {
	port := int32(5432)
	connection := models.NewBaseSecretConnectionDefinition()
	connection.SetHost(str("db.example.com"))
	connection.SetPort(&port)
	database := models.NewDatabaseBaseSecret()
	postgres := models.POSTGRES_DATABASEBASESECRET_TARGETTYPE
	database.SetTargetType(&postgres)
	database.SetConnection(connection)
	database.SetDatabase(str("orders"))
	database.SetCredential(credential())
	tenant := uuid.New()
	azure := models.NewAzureBaseSecret()
	azure.SetExternalTenantId(&tenant)
	azure.SetCredential(credential())

	gotDatabase, ok := read(t, write(t, database), models.CreateBaseSecretDefinitionFromDiscriminatorValue).(models.DatabaseBaseSecretable)
	if !ok || *gotDatabase.GetConnection().GetPort() != port || *gotDatabase.GetCredential().(models.UsernamePasswordCredentialable).GetUsername() != "admin" {
		t.Error("the database base secret was not preserved")
	}
	gotAzure, ok := read(t, write(t, azure), models.CreateBaseSecretDefinitionFromDiscriminatorValue).(models.AzureBaseSecretable)
	if !ok || *gotAzure.GetExternalTenantId() != tenant {
		t.Error("the azure base secret was not preserved")
	}
}

// A metadata definition is the base type; a type assertion picks the case.
func TestAMetadataDefinitionIsReadAsTheBaseTypeAndAssertedToItsCase(t *testing.T) {
	payload := read(t, []byte(`{"kind":"dynamic","metadata":{"version":1},"definition":{"type":"azureExistingApp","baseSecretPath":"infra/azure","appObjectId":"33333333-3333-3333-3333-333333333333"}}`),
		models.CreateSecretMetadataPayloadFromDiscriminatorValue).(models.SecretMetadataPayloadable)

	if _, ok := payload.GetDefinition().(models.AzureExistingAppDynamicSecretable); !ok {
		t.Errorf("the definition read back as %T, want the azureExistingApp case", payload.GetDefinition())
	}
}
